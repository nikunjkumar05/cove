import CoveCore
import Foundation

private final class MetadataQuerySession<Value> {
    let query = NSMetadataQuery()
    let box = ICloudDriveHelper.ObserverBox()
    let semaphore = DispatchSemaphore(value: 0)
    var finalizeWorkItem: DispatchWorkItem?

    private(set) var value: Value?
    private var didSignal = false

    func finish(_ value: Value, disableUpdates: Bool = false) {
        guard !didSignal else { return }
        didSignal = true
        finalizeWorkItem?.cancel()
        if disableUpdates {
            query.disableUpdates()
        }
        self.value = value
        query.stop()
        box.removeAll()
        semaphore.signal()
    }

    func finishOnMain(_ value: Value, disableUpdates: Bool = false) {
        DispatchQueue.main.async {
            self.finish(value, disableUpdates: disableUpdates)
        }
    }

    func wait(timeout: TimeInterval) -> Value? {
        guard semaphore.wait(timeout: .now() + timeout) != .timedOut else {
            return nil
        }
        return value
    }
}

extension ICloudDriveHelper {
    // MARK: - Cloud presence via NSMetadataQuery

    /// Runs an NSMetadataQuery and returns all matching items
    ///
    /// Must NOT be called from the main thread
    func metadataQuery(predicate: NSPredicate) throws -> [NSMetadataItem] {
        let session = MetadataQuerySession<Result<[NSMetadataItem], CloudStorageError>>()

        let captureResults = {
            (0 ..< session.query.resultCount).compactMap {
                session.query.result(at: $0) as? NSMetadataItem
            }
        }

        let finishQuery = { (reason: String) in
            let results = captureResults()
            Log.info(
                "metadataQuery: finalized reason=\(reason) count=\(results.count) predicate=\(predicate.predicateFormat)"
            )
            session.finish(.success(results), disableUpdates: true)
        }

        DispatchQueue.main.async {
            session.query.searchScopes = [NSMetadataQueryUbiquitousDataScope]
            session.query.predicate = predicate

            let scheduleFinalize = { (reason: String) in
                session.finalizeWorkItem?.cancel()
                let workItem = DispatchWorkItem {
                    finishQuery(reason)
                }
                session.finalizeWorkItem = workItem
                DispatchQueue.main.asyncAfter(
                    deadline: .now() + self.metadataSettleInterval,
                    execute: workItem
                )
            }

            session.box.add(
                NotificationCenter.default.addObserver(
                    forName: .NSMetadataQueryDidFinishGathering,
                    object: session.query,
                    queue: .main
                ) { _ in
                    Log.info(
                        "metadataQuery: finish gathering count=\(session.query.resultCount) predicate=\(predicate.predicateFormat)"
                    )
                    scheduleFinalize("finish")
                }
            )
            session.box.add(
                NotificationCenter.default.addObserver(
                    forName: .NSMetadataQueryDidUpdate,
                    object: session.query,
                    queue: .main
                ) { _ in
                    Log.info(
                        "metadataQuery: update count=\(session.query.resultCount) predicate=\(predicate.predicateFormat)"
                    )
                    scheduleFinalize("update")
                }
            )

            Log.info("metadataQuery: starting predicate=\(predicate.predicateFormat)")
            if !session.query.start() {
                session.box.removeAll()
                session.finish(.failure(.NotAvailable("failed to start iCloud metadata query")))
            }
        }

        guard let result = session.wait(timeout: defaultTimeout) else {
            session.finishOnMain(
                .failure(.NotAvailable("iCloud metadata query timed out"))
            )
            _ = session.wait(timeout: 1)
            throw CloudStorageError.NotAvailable("iCloud metadata query timed out")
        }

        switch result {
        case let .success(results):
            return results
        case let .failure(error):
            throw error
        }
    }

    /// Authoritatively checks whether a file exists in iCloud (finds evicted files too)
    ///
    /// Must NOT be called from the main thread
    func fileExistsInCloud(name: String) throws -> Bool {
        let predicate = NSPredicate(format: "%K == %@", NSMetadataItemFSNameKey, name)
        let results = try metadataQuery(predicate: predicate)
        return !results.isEmpty
    }

    /// Resolve symlinks so /var and /private/var compare correctly
    private static func resolvedPath(_ path: String) -> String {
        URL(fileURLWithPath: path).resolvingSymlinksInPath().path
    }

    private static func metadataPath(for item: NSMetadataItem) -> String? {
        if let path = item.value(forAttribute: NSMetadataItemPathKey) as? String {
            return resolvedPath(path)
        }
        if let url = item.value(forAttribute: NSMetadataItemURLKey) as? URL {
            return resolvedPath(url.path)
        }
        return nil
    }

    private static func resolvedItem(
        named name: String,
        under resolvedParent: String,
        in query: NSMetadataQuery
    ) -> ResolvedMetadataItem? {
        let prefix = resolvedParent + "/"

        for index in 0 ..< query.resultCount {
            guard let item = query.result(at: index) as? NSMetadataItem else {
                continue
            }
            guard let itemName = item.value(forAttribute: NSMetadataItemFSNameKey) as? String else {
                continue
            }
            guard itemName == name else { continue }
            guard let metadataURL = item.value(forAttribute: NSMetadataItemURLKey) as? URL else {
                continue
            }
            let metadataPath = Self.metadataPath(for: item)
            if let metadataPath, metadataPath.hasPrefix(prefix) {
                return ResolvedMetadataItem(url: metadataURL, metadataPath: metadataPath)
            }
        }

        return nil
    }

    private static func metadataItemSummary(_ item: NSMetadataItem) -> String {
        let name = (item.value(forAttribute: NSMetadataItemFSNameKey) as? String) ?? "<unknown>"
        let path = metadataPath(for: item) ?? "<no-path>"
        let url =
            ((item.value(forAttribute: NSMetadataItemURLKey) as? URL)?.path) ?? "<no-url>"
        return "name=\(name) path=\(path) url=\(url)"
    }

    private static func metadataItemSummaries(in query: NSMetadataQuery) -> [String] {
        (0 ..< query.resultCount).compactMap { index in
            guard let item = query.result(at: index) as? NSMetadataItem else {
                return nil
            }
            return metadataItemSummary(item)
        }
    }

    func logMetadataItems(
        under parentDirectoryURL: URL,
        reason: String,
        focusName: String
    ) {
        let resolvedParent = Self.resolvedPath(parentDirectoryURL.path)
        let session = MetadataQuerySession<Void>()

        let finish = {
            let summaries = Self.metadataItemSummaries(in: session.query)
            Log.info(
                "metadataItems: reason=\(reason) focus=\(focusName) parent=\(resolvedParent) count=\(summaries.count)"
            )
            for summary in summaries {
                Log.info("metadataItems: \(summary)")
            }
            session.finish(())
        }

        DispatchQueue.main.async {
            session.query.searchScopes = [parentDirectoryURL]
            session.query.predicate = NSPredicate(value: true)

            session.box.add(
                NotificationCenter.default.addObserver(
                    forName: .NSMetadataQueryDidFinishGathering,
                    object: session.query,
                    queue: .main
                ) { _ in
                    finish()
                }
            )
            session.box.add(
                NotificationCenter.default.addObserver(
                    forName: .NSMetadataQueryDidUpdate,
                    object: session.query,
                    queue: .main
                ) { _ in
                    finish()
                }
            )

            if !session.query.start() {
                Log.info(
                    "metadataItems: failed to start reason=\(reason) focus=\(focusName) parent=\(resolvedParent)"
                )
                session.box.removeAll()
                session.finish(())
            }
        }

        guard session.wait(timeout: 5) != nil else {
            session.finishOnMain(())
            _ = session.wait(timeout: 1)
            Log.info(
                "metadataItems: timed out reason=\(reason) focus=\(focusName) parent=\(resolvedParent)"
            )
            return
        }
    }

    func waitForMetadataItem(
        named name: String,
        parentDirectoryURL: URL,
        deadline: Date
    ) throws -> ResolvedMetadataItem {
        let resolvedParent = Self.resolvedPath(parentDirectoryURL.path)
        let predicate = NSPredicate(format: "%K == %@", NSMetadataItemFSNameKey, name)
        let session = MetadataQuerySession<Result<ResolvedMetadataItem, MetadataLookupError>>()

        let finish = { (item: ResolvedMetadataItem?, error: MetadataLookupError?) in
            if let error {
                session.finish(.failure(error))
                return
            }

            if let item {
                session.finish(.success(item))
                return
            }

            session.finish(
                .failure(.missingURL("iCloud metadata query finished without a URL for \(name)"))
            )
        }

        DispatchQueue.main.async {
            session.query.searchScopes = [NSMetadataQueryUbiquitousDataScope]
            session.query.predicate = predicate

            let evaluate = { (reason: String) in
                if let item = Self.resolvedItem(
                    named: name,
                    under: resolvedParent,
                    in: session.query
                ) {
                    Log.info(
                        "metadataLookup: resolved name=\(name) reason=\(reason) url=\(item.url.path) metadataPath=\(item.metadataPath ?? "<unknown>")"
                    )
                    finish(item, nil)
                    return
                }

                Log.info(
                    "metadataLookup: no match yet name=\(name) reason=\(reason) count=\(session.query.resultCount) parent=\(resolvedParent)"
                )
                for summary in Self.metadataItemSummaries(in: session.query) {
                    Log.info("metadataLookup: item \(summary)")
                }
            }

            session.box.add(
                NotificationCenter.default.addObserver(
                    forName: .NSMetadataQueryDidFinishGathering,
                    object: session.query,
                    queue: .main
                ) { _ in
                    evaluate("finish")
                }
            )
            session.box.add(
                NotificationCenter.default.addObserver(
                    forName: .NSMetadataQueryDidUpdate,
                    object: session.query,
                    queue: .main
                ) { _ in
                    evaluate("update")
                }
            )

            Log.info(
                "metadataLookup: starting name=\(name) parent=\(resolvedParent) predicate=\(predicate.predicateFormat)"
            )
            if !session.query.start() {
                finish(
                    nil,
                    .startFailed("failed to start iCloud metadata query for \(name)")
                )
            }
        }

        guard let result = session.wait(timeout: deadline.timeIntervalSinceNow) else {
            session.finishOnMain(
                .failure(.timedOut("iCloud metadata query timed out for \(name)"))
            )
            _ = session.wait(timeout: 1)
            throw MetadataLookupError.timedOut("iCloud metadata query timed out for \(name)")
        }

        switch result {
        case let .failure(failure):
            throw failure
        case let .success(resolvedItem):
            return resolvedItem
        }
    }

    func resolvedMetadataItemIfPresent(
        named name: String,
        parentDirectoryURL: URL
    ) -> ResolvedMetadataItem? {
        let resolvedParent = Self.resolvedPath(parentDirectoryURL.path)
        let predicate = NSPredicate(format: "%K == %@", NSMetadataItemFSNameKey, name)
        let session = MetadataQuerySession<ResolvedMetadataItem?>()

        let finish = {
            let match = Self.resolvedItem(named: name, under: resolvedParent, in: session.query)
            session.finish(match)
        }

        DispatchQueue.main.async {
            session.query.searchScopes = [NSMetadataQueryUbiquitousDataScope]
            session.query.predicate = predicate

            session.box.add(
                NotificationCenter.default.addObserver(
                    forName: .NSMetadataQueryDidFinishGathering,
                    object: session.query,
                    queue: .main
                ) { _ in
                    finish()
                }
            )
            session.box.add(
                NotificationCenter.default.addObserver(
                    forName: .NSMetadataQueryDidUpdate,
                    object: session.query,
                    queue: .main
                ) { _ in
                    finish()
                }
            )

            if !session.query.start() {
                finish()
            }
        }

        guard let match = session.wait(timeout: 5) else {
            session.finishOnMain(nil)
            _ = session.wait(timeout: 1)
            return nil
        }

        return match
    }

    private func metadataNames(
        parentDirectoryURL: URL,
        transform: (String) -> String?
    ) throws -> [String] {
        let resolvedParent = Self.resolvedPath(parentDirectoryURL.path)
        let pathPrefix = resolvedParent + "/"
        let items = try metadataQuery(predicate: NSPredicate(value: true))
        var names = Set<String>()

        for item in items {
            guard let metadataPath = Self.metadataPath(for: item) else { continue }
            guard metadataPath.hasPrefix(pathPrefix) else { continue }

            let relativePath = String(metadataPath.dropFirst(pathPrefix.count))
            guard let name = transform(relativePath) else { continue }
            names.insert(name)
        }

        return names.sorted()
    }

    func metadataSubdirectoryNames(parentDirectoryURL: URL) throws -> [String] {
        try metadataNames(parentDirectoryURL: parentDirectoryURL) { relativePath in
            guard let firstComponent = relativePath.split(separator: "/").first else {
                return nil
            }
            return String(firstComponent)
        }
    }

    func metadataFileNames(parentDirectoryURL: URL, prefix: String) throws -> [String] {
        try metadataNames(parentDirectoryURL: parentDirectoryURL) { relativePath in
            guard !relativePath.contains("/") else { return nil }
            let name = URL(fileURLWithPath: relativePath).lastPathComponent
            guard name.hasPrefix(prefix) else { return nil }
            return name
        }
    }
}
