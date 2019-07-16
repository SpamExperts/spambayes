"""
This is the place where we try and discover information buried in images.
"""

# XXX Consider tokens for palette, presence of animation and compression ratio

from __future__ import division

import re
import os
import sys
import md5
import ssl
import math
import time
import atexit
import socket
import struct
import urllib2
import httplib
import logging
import tempfile
import warnings
import subprocess
try:
    import cPickle as pickle
except ImportError:
    import pickle
try:
    import cStringIO as StringIO
except ImportError:
    import StringIO

try:
    from PIL import Image, ImageSequence
    from PIL.Image import DecompressionBombWarning
except ImportError:
    Image = None

# The email mime object carrying the image data can have a special attribute
# which indicates that a message had an image, but it was large (ie, larger
# than the 'max_image_size' option.)  This allows the provider of the email
# object to avoid loading huge images into memory just to have this image
# stripper ignore it.
# If the attribute exists, it should be the size of the image (we assert it
# is > max_image_size).  The image payload is ignored.
# A 'cleaner' option would be to look at a header - but an attribute was
# chosen to avoid spammers getting wise and 'injecting' the header into the
# message body of a mime section.
image_large_size_attribute = "spambayes_image_large_size"

try:
    # We have three possibilities for Set:
    #    (a) With Python 2.2 and earlier, we use our compatsets class
    #    (b) With Python 2.3, we use the sets.Set class
    #    (c) With Python 2.4 and later, we use the builtin set class
    Set = set
except NameError:
    try:
        from sets import Set
    except ImportError:
        from spambayes.compatsets import Set

import spambayes
import spambayes.sb_logging
from spambayes.Options import options as global_options
# XXX This is circular.
from spambayes.tokenizer import Stripper, URLStripper, tokenize, img_url_fancy_re

spambayes.sb_logging.setup()
logger = logging.getLogger('spambayes')


def parts(walk):
    """Message parts that are able to be handled by this module.

    "Return a list of all msg parts with type 'image/*'."""
    # We don't want a set here because we want to be able to process them
    # in order.
    return [part for part in walk()
            if part.get_content_maintype() == "image"]


# copied from tokenizer.py - maybe we should split it into pieces...
def log2(n, log=math.log, c=math.log(2)):
    return log(n)/c


def is_executable(prog):
    if sys.platform == "win32":
        return True
    info = os.stat(prog)
    return (info.st_uid == os.getuid() and (info.st_mode & 0100) or
            info.st_gid == os.getgid() and (info.st_mode & 0010) or
            info.st_mode & 0001)


def find_program(prog):
    path = os.environ.get("PATH", "").split(os.pathsep)
    if sys.platform == "win32":
        prog = "%s.exe" % prog
        if hasattr(sys, "frozen"):  # a binary (py2exe) build..
            # Outlook plugin puts executables in (for example):
            #    C:/Program Files/SpamBayes/bin
            # so add that directory to the path and make sure we
            # look for a file ending in ".exe".
            import win32api
            if sys.frozen == "dll":
                sentinal = win32api.GetModuleFileName(sys.frozendllhandle)
            else:
                sentinal = sys.executable
            # os.popen() trying to quote both the program and argv[1] fails.
            # So just use the short version.
            # For the sake of safety, in a binary build we *only* look in
            # our bin dir.
            path = [win32api.GetShortPathName(os.path.dirname(sentinal))]
        else:
            # a source build - for testing, allow it in SB package dir.
            import spambayes
            path.insert(0, os.path.abspath(spambayes.__path__[0]))
    elif sys.platform == "linux2" and (not path or path == [""]):
        # If there's no PATH available, then take a guess at what would be
        # reasonable on this platform.
        path = ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin",
                "/usr/bin", "/sbin", "/bin"]

    for directory in path:
        program = os.path.join(directory, prog)
        if os.path.exists(program) and is_executable(program):
            return program
    return ""


def imconcatlr(left, right):
    """Concatenate two images left to right."""
    w1, h1 = left.size
    w2, h2 = right.size
    result = Image.new("RGB", (w1 + w2, max(h1, h2)))
    result.paste(left, (0, 0))
    result.paste(right, (w1, 0))
    return result


def imconcattb(upper, lower):
    """Concatenate two images top to bottom."""
    w1, h1 = upper.size
    w2, h2 = lower.size
    result = Image.new("RGB", (max(w1, w2), h1 + h2))
    result.paste(upper, (0, 0))
    result.paste(lower, (0, h1))
    return result


def decode_parts(parts, image_handler, options=global_options):
    """Decode and assemble a bunch of images using PIL."""
    rows = []
    combined_size = 0
    max_image_size = options["Tokenizer", "max_image_size"]
    min_image_width = options["Tokenizer", "min_image_width"]
    min_image_height = options["Tokenizer", "min_image_height"]
    for part in parts:
        # See 'image_large_size_attribute' above - the provider may have seen
        # an image, but optimized the fact we don't bother processing large
        # images.
        nbytes = getattr(part, image_large_size_attribute, None)
        if nbytes is None:  # no optimization - process normally...
            try:
                bytes = part.get_payload(decode=True)
                nbytes = len(bytes)
            except:
                yield "invalid-image:%s" % part.get_content_type()
                continue
        else:
            # optimization should not have remove images smaller than our max
            assert nbytes > max_image_size, (len(bytes), max_image_size)

        if nbytes > max_image_size:
            yield "image:big"
            continue                # assume it's just a picture for now

        # We're dealing with spammers and virus writers here.  Who knows
        # what garbage they will call a GIF image to entice you to open
        # it?
        try:
            warnings.filterwarnings("error", category=DecompressionBombWarning)
            image = Image.open(StringIO.StringIO(bytes))
            image.load()
        except DecompressionBombWarning:
            warnings.resetwarnings()
            yield "image:big"
            continue
        except:
            warnings.resetwarnings()
            # Any error whatsoever is reason for not looking further at
            # the image.
            yield "invalid-image:%s" % part.get_content_type()
            continue
        else:
            warnings.resetwarnings()
            # It's possible to get images that have a tiny amount of data
            # but are meant to decompress to huge images.  For example, I've
            # seen a 2K GIF that is meant to be 1121 MP when decompressed.
            # Since we need the full uncompressed image to pass to the OCR
            # decoding and we hold that in memory, the decompressed size is
            # also very important.
            nbytes = image.size[0] * image.size[1]
            if nbytes > max_image_size:
                yield "image:big"
                continue
            # Spammers are now using GIF image sequences.  From examining a
            # miniscule set of multi-frame GIFs it appears the frame with
            # the fewest number of background pixels is the one with the
            # text content.
            if "duration" in image.info:
                # Big assumption?  I don't know.  If the image's info dict
                # has a duration key assume it's a multi-frame image.  This
                # should save some needless construction of pixel
                # histograms for single-frame images.
                bgpix = 1e17           # ridiculously large number of pixels
                try:
                    for frame in ImageSequence.Iterator(image):
                        # Assume the pixel with the largest value is the
                        # background.
                        bg = max(frame.histogram())
                        if bg < bgpix:
                            image = frame
                            bgpix = bg
                # I've empirically determined:
                #   * ValueError => GIF image isn't multi-frame.
                #   * IOError => Decoding error
                #   * struct.error => GIF, but not sure what the problem is
                except IOError:
                    yield "invalid-image:%s" % part.get_content_type()
                    continue
                except (ValueError, IndexError, struct.error):
                    pass
                except UnboundLocalError as e:
                    # Upstream issue with Pillow:
                    # https://github.com/python-pillow/Pillow/pull/2363
                    pass
                except TypeError:
                    yield "invalid-image:%s" % part.get_content_type()

            # XXX Temporarirly skip tiff images until the issue with Pillow is
            # XXX fixed upstream (#20513)
            if image.format.lower() == 'tiff':
                logger.debug("Skipping TIFF image")
                continue

            if image.mode.lower() == "lab":
                # Pillow does not have support for this image type yet. (#20578)
                logger.debug("Skipping LAB image")
                continue

            try:
                image = image.convert("RGB")
            except ValueError:
                yield "invalid-image:%s" % part.get_content_type()
                continue
            except UnboundLocalError:
                # It seems like this is a bug in PIL.  Ignore the image.
                continue
            except TypeError:
                # It seems like this is a bug in PIL.  Ignore the image.
                continue

        # One trick that spammers play is to break up an image into many
        # smaller parts - the image then can't easy be processed, but will
        # display the same.  To combat this, we combine the images into a
        # single larger image.  However, this does not work well when there
        # are many large images in the email, which often occurs in ham.
        # XXX This system has not been extensively tested; there are
        # XXX almost certainly improvements that could be made.
        # If an image is larger than max_image_size pixels, then we process
        # it individually as well as add it into the combined image.
        if image.size[0] * image.size[1] > max_image_size:
            if (image.size[0] > min_image_width and
                    image.size[1] > min_image_height):
                for token in image_handler(image):
                    yield token
        # If the combined image ends up larger than 1920x1200 pixels, then
        # we stop adding images to it (that's so large that displayed at
        # full size the viewer probably wouldn't see anything else anyway;
        # a spammer could rely on auto-scaling, but we'll deal with that if
        # it becomes a problem).
        # XXX To simplify the calculations, we actually don't check if the
        # XXX image size is over 1920x1200, but if the number of pixels in
        # XXX the individual images sum to more than that.  This means that
        # XXX if there are many images with different heights and widths
        # XXX the combined image could actually be larger.
        if combined_size < 1920 * 1200:
            combined_size += (image.size[0] * image.size[1])
            if not rows:
                # first image
                rows.append(image)
            elif image.size[1] != rows[-1].size[1]:
                # new image, different height => start new row
                rows.append(image)
            else:
                # new image, same height => extend current row
                rows[-1] = imconcatlr(rows[-1], image)
    if not rows:
        return
    # Now concatenate the resulting row images top-to-bottom.
    full_image, rows = rows[0], rows[1:]
    for image in rows:
        full_image = imconcattb(full_image, image)
    if (full_image.size[0] > min_image_width and
            full_image.size[1] > min_image_height):
        for token in image_handler(full_image):
            yield token


class OCREngine(object):
    """Base class for an OCR "engine" that extracts text."""
    engine_name = None  # sub-classes should override.
    image_format = "PPM"  # format for images to be saved in.

    def __init__(self, options=global_options):
        self.options = options

    def is_enabled(self, options=global_options):
        """Return true if this engine is able to be used.  Note that
           returning true only means it is *capable* of being used - not that
           it is enabled.  eg, it should check the program it needs to use
           is installed, etc.
        """
        raise NotImplementedError

    def extract_text(self, pnmfiles):
        """Extract the text as an unprocessed stream (but as a string).
           Typically this will be the raw output from the OCR engine.
        """
        raise NotImplementedError


class OCRExecutableEngine(OCREngine):
    """Uses a simple executable that writes to stdout to extract the text"""
    engine_name = None

    def __init__(self, options=global_options):
        # we go looking for the program first use and cache its location
        self._program = None
        OCREngine.__init__(self, options)

    def is_enabled(self, options=global_options):
        return self.program is not None

    def get_program(self):
        # by default, executable is same as engine name
        if not self._program:
            self._program = find_program(self.engine_name)
        return self._program

    program = property(get_program)


class OCREngineOCRAD(OCRExecutableEngine):
    engine_name = "ocrad"

    def extract_text(self, pnmfile):
        assert self.is_enabled(), "I'm not working!"
        scale = self.options["Tokenizer", "ocrad_scale"] or 1
        charset = self.options["Tokenizer", "ocrad_charset"]
        ocr = subprocess.Popen([self.program, "-s", str(scale), "-c",
                                charset, "-f", pnmfile],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               stdin=subprocess.PIPE)
        data = ocr.communicate()[0]
        return data


class OCREngineGOCR(OCRExecutableEngine):
    engine_name = "gocr"

    def extract_text(self, pnmfile):
        assert self.is_enabled(), "I'm not working!"
        ocr = subprocess.Popen('%s "%s"' %
                               (self.program, pnmfile), shell=True,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               stdin=subprocess.PIPE)
        data = ocr.communicate()[0]
        return data


class OCREngineTesseract(OCRExecutableEngine):
    engine_name = "tesseract"
    image_format = "TIFF"

    def extract_text(self, tiffile):
        assert self.is_enabled(), "I'm not working!"
        fd, resultsfile = tempfile.mkstemp('-spambayes-image-results')
        os.close(fd)
        ocr = subprocess.Popen('%s "%s" "%s"' %
                               (self.program, tiffile, resultsfile),
                               stdout=subprocess.PIPE,
                               stdin=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               shell=True)
        ocr.communicate()
        retfile = open(resultsfile + ".txt", "rb")
        ret = retfile.read()
        retfile.close()
        try:
            os.remove(resultsfile + ".txt")
        except OSError:
            pass
        return ret


class OCREnginePyTesseract(OCREngine):
    """Use tesseract, but via the pytesseract package."""
    engine_name = "pytesseract"
    image_format = None

    def __init__(self, options=global_options):
        self.program = find_program("tesseract")
        OCREngine.__init__(self, options)

    def is_enabled(self, options=global_options):
        """Return true if this engine is able to be used."""
        try:
            import pytesseract
        except ImportError:
            return False
        return self.program

    def extract_text(self, image):
        """Extract the text as an unprocessed stream (but as a string)."""
        import pytesseract
        pytesseract.pytesseract.tesseract_cmd = self.program
        if image.format.lower() in ("tiff", "lab"):
            return
        try:
            return pytesseract.image_to_string(image).encode("utf8", "replace")
        except UnicodeError:
            pass


class OCREngineCachedRekognition(OCREngine):
    """Use AWS's Rekognition service to provide OCR, via previously cached
    result files.
    
    *This cannot be used in production!*"""
    engine_name = "cached-rekognition"
    image_format = None
    program = "rekonition"  # Must be truthy.
    confidence = 90.0  # Threshold for AWS Rekogition confidence.

    def is_enabled(self, options=global_options):
        """Return true if this engine is able to be used."""
        try:
            import dhash
        except ImportError:
            return False
        cache = options["Tokenizer", "x-rekognition_cache"]
        return os.path.isdir(cache)

    def extract_text(self, image):
        """Provide the text from the cached Rekognition data."""
        if not image.format.lower() in ("png", "jpeg"):
            return
        import dhash
        try:
            row, col = dhash.dhash_row_col(image)
        except OSError:
            return
        img_hash = str(int(dhash.format_hex(row, col), 16))
        cache = self.options["Tokenizer", "x-rekognition_cache"]
        try:
            with open(os.path.join(cache, img_hash + ".json")) as inf:
                data = json.load(inf)
        except IOError:
            return
        if not data or "TextDetections" not in data:
            return
        # We have lots of information about locations and parents and so on,
        # but just generate a stream of text, because we're converting it
        # all into a bag of tokens anyway.
        return "".join({text["DetectedText"]
                        for text in data["TextDetections"]
                        if text["Confidence"] < self.confidence})


# This lists all engines, with the first listed that is enabled winning.
# Matched with the engine name, as specified in Options.py, via the
# 'engine_name' attribute on the class.
_ocr_engines = [
    OCREngineGOCR,
    OCREngineOCRAD,
    OCREngineTesseract,
    OCREnginePyTesseract,
    OCREngineCachedRekognition,
]


def get_engine(engine_name, options=global_options):
    if not engine_name:
        candidates = _ocr_engines
    else:
        for e in _ocr_engines:
            if e.engine_name == engine_name:
                candidates = [e]
                break
        else:
            candidates = []
    for candidate in candidates:
        engine = candidate()
        if engine.is_enabled(options):
            return engine
    return None


class ImageStripper(object):
    def __init__(self, cachefile="", options=global_options):
        self.cachefile = os.path.expanduser(cachefile)
        if os.path.exists(self.cachefile):
            cachefile = open(self.cachefile)
            try:
                self.cache = pickle.load(cachefile)
            except (TypeError, pickle.UnpicklingError, AttributeError,
                    ValueError, EOFError):
                # Bad cache - wipe it.
                self.cache = {}
            cachefile.close()
        else:
            self.cache = {}
        self.misses = self.hits = 0
        if self.cachefile:
            atexit.register(self.close)
        self.engine = None
        self.options = options

    def extract_ocr_info(self, image):
        # Late import to avoid any circular dependancies.
        import spambayes.tokenizer
        assert self.engine, "must have an engine!"
        try:
            fhash = md5.new("".join(chr(a) for p in image.getdata()
                                    for a in p)).hexdigest()
        except SystemError:
            # This happens with a "tile cannot extend outside image" error.
            yield "image-to-string-error"
            return
        if fhash in self.cache:
            self.hits += 1
            for token in self.cache[fhash]:
                yield token
            return
        self.misses += 1
        if not self.engine.program:
            # We should not get here if no OCR is enabled.  If it
            # is enabled and we have no program, its OK to spew lots
            # of warnings - they should either disable OCR (it is by
            # default), or fix their config.
            logger.warning("No OCR program '%s' available - can't "
                           "get text!" % self.engine.engine_name)
            return
        if self.engine.image_format:
            fd, pnmfilename = tempfile.mkstemp('-spambayes-image')
            os.close(fd)
            try:
                pnmfile = open(pnmfilename, "wb")
                try:
                    image.save(pnmfile, self.engine.image_format)
                except IOError as e:
                    if e.errno == 28:
                        logger.info("No space left to save image for OCR %s", e)
                        return
                    raise
                pnmfile.close()
                text = self.engine.extract_text(pnmfilename)
            finally:
                try:
                    os.remove(pnmfilename)
                except OSError:
                    logger.info("Couldn't remove image: " + pnmfilename)
        else:
            text = self.engine.extract_text(image)
        tokens_to_cache = []
        for token in self.generate_tokens(text):
            yield token
            tokens_to_cache.append(token)
        self.cache[fhash] = tokens_to_cache

    def generate_tokens(self, text):
        """Generate tokens based on the OCR'd text."""
        if not text.strip():
            # Lots of spam now contains images in which it is difficult or
            # impossible (using OCR) to find any text. Make a note of that.
            token = "image-text:no text found"
            yield token
            return
        tokenize_text = spambayes.tokenizer.Tokenizer(self.options).tokenize_text
        tokens = Set(tokenize_text(text.lower()))
        nlines = len(text.strip().split("\n"))
        if nlines:
            tokens.add("image-text-lines:%d" % int(log2(nlines)))
        for token in tokens:
            yield token

    def tokenize(self, parts):
        # If there are no parts, then we are already done.
        if not parts:
            return
        # If PIL is not available, then we cannot generate any tokens.
        if not Image:
            return
        engine_name = self.options["Tokenizer", 'x-ocr_engine']
        # Check engine hasn't changed...
        if self.engine is not None and self.engine.engine_name != engine_name:
            self.engine = None
        # Check engine exists and is valid.
        if self.engine is None:
            self.engine = get_engine(engine_name, self.options)
        if self.engine is None:
            # We only get here if explicitly enabled - spewing msgs is ok.
            logger.warning("invalid engine name '%s' - OCR disabled" %
                           (engine_name,))
            return
        for token in decode_parts(parts, self.extract_ocr_info, self.options):
            yield token

    def close(self):
        message = "saving %d items to %s" % \
                  (len(self.cache), self.cachefile)
        if self.hits + self.misses:
            message += " %.2f%% hit rate" % \
                       (100 * self.hits / (self.hits + self.misses))
        logger.info(message)
        cachefile = open(self.cachefile, "wb")
        pickle.dump(self.cache, cachefile)
        cachefile.close()


# Waiting for the default timeout period slows everything
# down far too much.
original_timeout = socket.getdefaulttimeout()


def set_timeout(timeout):
    try:
        socket.setdefaulttimeout(timeout)
    except AttributeError:
        # Probably Python 2.2.
        pass


def restore_timeout():
    try:
        socket.setdefaulttimeout(original_timeout)
    except AttributeError:
        # Probably Python 2.2.
        pass


class dummy_part2(object):
    def __init__(self, content, content_type, subtype):
        self.content = content
        self.content_type = content_type
        self.subtype = subtype

    def get_payload(self, decode=True):
        return self.content

    def get_content_type(self):
        return self.content_type

    def get_content_subtype(self):
        return self.subtype


class SlurpingImageStripper(URLStripper):
    def __init__(self, options=global_options):
        self.options = options
        search = img_url_fancy_re.search
        Stripper.__init__(self, search, re.compile("").search)

    def retrieve_file(self, proto, url, tokens=None, exts=None):
        # Check if we already have this image in our cache.
        hashed_url = md5.md5(url.encode("us-ascii", "replace")).hexdigest()
        cached_image = os.path.join(tempfile.gettempdir(), "image-cache",
                                    hashed_url)
        logger.debug("Looking for %s://%s (cached: %s)" %
                     (proto, url, os.path.exists(cached_image)))

        try:
            with open(cached_image, "rb") as cachefile:
                cache = cachefile.read().split("\n", 1)
        except IOError:
            pass
        else:
            # Touch the file, so that the modification date changes - this
            # means that sorting by modification date will sort by images
            # that have recently been used.  This allows for a simple method
            # of expiring images from the cache.  A more sophisticated
            # method (taking into account the number of accesses, the size
            # of the file, etc) could be done, but would require storing
            # this meta-data somewhere, and it doesn't seem worth doing
            # that.
            try:
                os.utime(cached_image, None)
            except OSError:
                # Presumably it was just removed from the cache.  Ignore
                # this (i.e. live with the expiry rather than re-caching it).
                pass
            if len(cache) == 2:
                # Maybe it was tokens that was cached, not the image (e.g. there
                # was an error retrieving).  These errors could be temporary,
                # but are probably not, and we really want the speed of the
                # cached access.  The cached values will eventually expire in
                # most cases, so will be replaced.
                if cache[0] == "token":
                    tokens.extend(cache[1].split(','))
                    return
                return cache
            logger.debug("Bad cache data: %s" % (cached_image,))
            try:
                os.remove(cached_image)
            except OSError, e:
                logger.info("Unable to remove cache file: %s", e)
        if not tokens:
            tokens = []
        if not exts:
            exts = ('.arg', '.bmp', '.cur', '.dcx', '.eps', '.fli', '.fpx',
                    '.gbr', '.icns', '.ico', '.im', '.imt', '.iptc',
                    '.jpeg', '.jpg', '.mcidas', '.mic', '.mpeg', '.msp',
                    '.pcd', '.pcx', '.pixar', '.png', '.ppm', '.psd',
                    '.sgi', '.spider', '.sun', '.tga', '.tiff', '.wbmp',
                    '.xbm', '.xpm', '.xvthumb')
        if exts != "*" and os.path.splitext(url)[1].lower() not in exts:
            self._cache_image(cached_image, "token", "url:non_image")
            tokens.append("url:non_image")
            return
        # If there is no content in the URL, then just return immediately.
        # "http://)" will trigger this.
        if not url:
            self._cache_image(cached_image, "token", "url:non_resolving")
            tokens.append("url:non_resolving")
            return
        # We check if the url will resolve first.
        mo = re.match(r"([^:/\\]+)(:([\d]+))?", url)
        if not mo:
            self._cache_image(cached_image, "token", "url:non_resolving")
            tokens.append("url:non_resolving")
            return
        domain = mo.group(1)
        if mo.group(3) is None:
            port = 80
        else:
            port = mo.group(3)
        # XXX We could do an IPv6 check here as well, but we should use
        # XXX the dnscache module to handle the lookup. For now, the IPv4
        # XXX token is enough, and any issues with non-resolving IPv6
        # XXX addresses can just get the more generic errors covered
        # XXX below.
        try:
            socket.gethostbyname(domain)
        except (socket.error, UnicodeError):
            self._cache_image(cached_image, "token", "url:non_resolving")
            tokens.append("url:non_resolving")
            return
        set_timeout(5)
        try:
            try:
                req = urllib2.Request("%s://%s" % (proto, url),
                                      headers={"User-Agent":
                                               "SpamBayes/%s (Image)" %
                                      spambayes.__version__})
                if hasattr(ssl, '_create_unverified_context'):
                    ssl_context = ssl._create_unverified_context()
                    f = urllib2.urlopen(req, context=ssl_context)
                else:
                    f = urllib2.urlopen(req)
            except (urllib2.URLError, socket.error, httplib.error,
                    ValueError), e:
                mo = re.match(r"HTTP Error ([\d]+)", str(e))
                if mo:
                    tokens.append("url:http_" + mo.group(1))
                    if mo.group(1)[0] == "4":
                        self._cache_image(cached_image, "token",
                                          "url:http_" + mo.group(1))
                else:
                    tokens.append("url:unknown_error")
                return
            except (UnicodeEncodeError, UnicodeDecodeError), e:
                self._cache_image(cached_image, "token", "url:unicode")
                tokens.append("url:unicode")
                return
        finally:
            restore_timeout()
        # Get the headers first.
        try:
            content_type = f.info().get('content-type') or ""
        except (socket.error, ValueError):
            # This is probably a temporary error, like a timeout, so set it
            # to expire quickly.
            self._cache_image(cached_image, "token", "url:timed_out")
            os.utime(cached_image, (time.time(), time.time()-7*60*60*24))
            return
        # Get the image itself.
        try:
            content = f.read()
            f.close()
        except (socket.error, ValueError, httplib.error):
            # This is probably a temporary error, like a timeout, so set it
            # to expire quickly.
            self._cache_image(cached_image, "token", "url:timed_out")
            os.utime(cached_image, (time.time(), time.time()-7*60*60*24))
            return
        self._cache_image(cached_image, content_type, content)
        return content_type, content

    def _cache_image(self, filename, content_type, content):
        # Cache the image.
        try:
            os.makedirs(os.path.dirname(filename))
        except OSError:
            pass
        cached_image = open(filename, "wb")
        cached_image.write(content_type.replace("\n", " ") + "\n")
        cached_image.write(content)
        cached_image.close()

    def tokenize(self, m):
        # We generate these tokens:
        #  url:non_resolving
        #  url:http_XXX (for each type of http error encounted,
        #                for example 404, 403, ...)
        # And tokenise the received image.
        if not Image:
            return []
        proto, url = m.groups()
        if proto != "http":
            return []
        while url and url[-1] in '.:;?!/)':
            url = url[:-1]
        tokens = []
        result = self.retrieve_file(proto, url, tokens, "*")
        if result is None:
            return tokens
        content_type, content = result
        # Anything that isn't an image is ignored.
        if not content_type or not content_type.startswith("image"):
            tokens.append("url:non_image")
            return tokens
        content = [dummy_part2(content, content_type, "slurped")]
        engine_name = global_options["Tokenizer", 'x-ocr_engine']
        # Check engine hasn't changed...
        if _global_stripper.engine is not None and \
           _global_stripper.engine.engine_name != engine_name:
            _global_stripper.engine = None
        # Check engine exists and is valid.
        if _global_stripper.engine is None:
            _global_stripper.engine = get_engine(engine_name, global_options)
        if _global_stripper.engine is None:
            # We only get here if explicitly enabled - spewing msgs is ok.
            logger.warning("invalid engine name '%s' - OCR disabled" %
                           (engine_name,))
            return []
        tokens.extend(list(decode_parts(content, extract_ocr_info,
                           global_options)))
        return tokens

_cachefile = global_options["Tokenizer", "crack_image_cache"]
_global_stripper = ImageStripper(_cachefile)
extract_ocr_info = _global_stripper.extract_ocr_info
tokenize = _global_stripper.tokenize
crack_urls_slurp_images = SlurpingImageStripper(global_options).analyze
