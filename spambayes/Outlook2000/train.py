#! /usr/bin/env python
# Train a classifier from Outlook Mail folders
# Authors: Sean D. True, WebReply.Com, Mark Hammond
# October, 2002
# Copyright PSF, license under the PSF license

import traceback
from win32com.mapi import mapi

try:
    True, False
except NameError:
    # Maintain compatibility with Python 2.2
    True, False = 1, 0


# Note our Message Database uses PR_SEARCH_KEY, *not* PR_ENTRYID, as the
# latter changes after a Move operation - see msgstore.py
def been_trained_as_ham(msg, mgr):
    if not mgr.message_db.has_key(msg.searchkey):
        return False
    return mgr.message_db[msg.searchkey]=='0'

def been_trained_as_spam(msg, mgr):
    if not mgr.message_db.has_key(msg.searchkey):
        return False
    return mgr.message_db[msg.searchkey]=='1'

def train_message(msg, is_spam, mgr, rescore=False):
    # Train an individual message.
    # Returns True if newly added (message will be correctly
    # untrained if it was in the wrong category), False if already
    # in the correct category.  Catch your own damn exceptions.
    # If re-classified AND rescore = True, then a new score will
    # be written to the message (so the user can see some effects)
    from spambayes.tokenizer import tokenize

    if not mgr.message_db.has_key(msg.searchkey):
        was_spam = None
    else:
        was_spam = mgr.message_db[msg.searchkey]=='1'
    if was_spam == is_spam:
        return False    # already correctly classified

    # Brand new (was_spam is None), or incorrectly classified.
    stream = msg.GetEmailPackageObject()
    if was_spam is not None:
        # The classification has changed; unlearn the old classification.
        mgr.bayes.unlearn(tokenize(stream), was_spam)

    # Learn the correct classification.
    mgr.bayes.learn(tokenize(stream), is_spam)
    mgr.message_db[msg.searchkey] = ['0', '1'][is_spam]
    mgr.bayes_dirty = True

    # Simplest way to rescore is to re-filter with all_actions = False
    if rescore:
        import filter
        filter.filter_message(msg, mgr, all_actions = False)

    return True

# Untrain a message.
# Return: None == not previously trained
#         True == was_spam
#         False == was_ham
def untrain_message(msg, mgr):
    from spambayes.tokenizer import tokenize
    stream = msg.GetEmailPackageObject()
    if been_trained_as_spam(msg, mgr):
        assert not been_trained_as_ham(msg, mgr), "Can't have been both!"
        mgr.bayes.unlearn(tokenize(stream), True)
        del mgr.message_db[msg.searchkey]
        mgr.bayes_dirty = True
        return True
    if been_trained_as_ham(msg, mgr):
        assert not been_trained_as_spam(msg, mgr), "Can't have been both!"
        mgr.bayes.unlearn(tokenize(stream), False)
        del mgr.message_db[msg.searchkey]
        mgr.bayes_dirty = True
        return False
    return None

def train_folder(f, isspam, mgr, progress):
    num = num_added = 0
    for message in f.GetMessageGenerator():
        if progress.stop_requested():
            break
        progress.tick()
        try:
            if train_message(message, isspam, mgr):
                num_added += 1
        except:
            print "Error training message '%s'" % (message,)
            traceback.print_exc()
        num += 1
    print "Checked", num, "in folder", f.name, "-", num_added, "new entries found."

# Called back from the dialog to do the actual training.
def trainer(mgr, progress):
    config = mgr.config
    rebuild = config.training.rebuild
    rescore = config.training.rescore

    if not config.training.ham_folder_ids or not config.training.spam_folder_ids:
        progress.error("You must specify at least one spam, and one good folder")
        return

    if rebuild:
        mgr.InitNewBayes()
    bayes = mgr.bayes
    # We do this in possibly 3 stages - train, filter, save
    # re-scoring is much slower and training (as we actually have to save
    # the message back.)
    # Saving is really slow sometimes, but we only have 1 tick for that anyway
    if rescore:
        stages = ("Training", .3), ("Saving", .1), ("Scoring", .6)
    else:
        stages = ("Training", .9), ("Saving", .1)
    progress.set_stages(stages)

    progress.set_status("Counting messages")

    num_msgs = 0
    for f in mgr.message_store.GetFolderGenerator(config.training.ham_folder_ids, config.training.ham_include_sub):
        num_msgs += f.count
    for f in mgr.message_store.GetFolderGenerator(config.training.spam_folder_ids, config.training.spam_include_sub):
        num_msgs += f.count

    progress.set_max_ticks(num_msgs+3)

    for f in mgr.message_store.GetFolderGenerator(config.training.ham_folder_ids, config.training.ham_include_sub):
        progress.set_status("Processing good folder '%s'" % (f.name,))
        train_folder(f, 0, mgr, progress)
        if progress.stop_requested():
            return

    for f in mgr.message_store.GetFolderGenerator(config.training.spam_folder_ids, config.training.spam_include_sub):
        progress.set_status("Processing spam folder '%s'" % (f.name,))
        train_folder(f, 1, mgr, progress)
        if progress.stop_requested():
            return

    progress.tick()
    if progress.stop_requested():
        return
    # Completed training - save the database
    # Setup the next "stage" in the progress dialog.
    progress.set_max_ticks(1)
    progress.set_status("Writing the database...")
    mgr.Save()
    progress.tick()

    if rescore:
        # Setup the "filter now" config to what we want.
        config = mgr.config.filter_now
        config.only_unread = False
        config.only_unseen = False
        config.action_all = False
        config.folder_ids = mgr.config.training.ham_folder_ids + mgr.config.training.spam_folder_ids
        config.include_sub = mgr.config.training.ham_include_sub or mgr.config.training.spam_include_sub
        import filter
        filter.filterer(mgr, progress)

    progress.set_status("Completed training with %d spam and %d good messages" % (bayes.nspam, bayes.nham))

def main():
    import manager
    mgr = manager.GetManager()

    import dialogs.TrainingDialog
    d = dialogs.TrainingDialog.TrainingDialog(mgr, trainer)
    d.DoModal()

    mgr.Save()
    mgr.Close()

if __name__ == "__main__":
    main()
