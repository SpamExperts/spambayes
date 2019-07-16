import sys
import logging
import logging.handlers

setup_done = False
def setup():
    global setup_done
    logger = logging.getLogger('spambayes')
    logger.setLevel(logging.DEBUG)
    # Only add a handler if there isn't one already setup.
    if not logger.handlers:
        if sys.platform == "win32":
            handler = logging.StreamHandler()
        else:
            try:
                handler = logging.handlers.TimedRotatingFileHandler(\
                    "/var/log/spamexperts/spambayes.log", "midnight", 1, 10)
            except IOError:
                handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        handler.setFormatter(formatter)
        handler.setLevel(logging.DEBUG)
        logger.addHandler(handler)
    setup_done = True
