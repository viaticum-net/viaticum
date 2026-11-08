# What Viaticum promises today (alpha)

- This is alpha software. Keep another backup of anything you can't afford to lose.
- The contents of your files are encrypted on your machine before they leave it; friends who store the pieces can't read them. File names and folder structure are encrypted too. Nodes that carry service messages for you can see which friends hold your data and when you check on them or delete from them. Encryption does not protect you from malware on your own machine.
- The network keeps the current state of your folders, not a long history. Earlier versions and deleted files stay restorable for about four weeks, then leave. Moving a file to the trash counts as deleting it. Don't delete local files to free space.
- A new node gives before it gets: friends may take weeks to make room for your files. The dashboard shows how much is protected.
- Restoring is slow by design, may need a retry, and can take days.
- Your 24-word recovery phrase is the only way back if this machine is lost. Nobody, including us, can recover it. It is also stored on this machine, so anyone who can read your files can read it.
- Files larger than the limit shown in `viaticum status` are not backed up yet.
- Several devices under one phrase is experimental; those devices can read each other's data.
- The download is checked against a signature. The signing key's fingerprint is published on our GitHub page, next to the release itself. That catches a damaged or swapped download, but not a release published by someone who took over our GitHub account.
- Updates may break compatibility while we are in alpha.
