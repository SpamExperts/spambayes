from __future__ import division

# XXX To-do:
# XXX     1. There are some PDFs that are encrypted/secured that a regular
# XXX        PDF viewer can display, but decrypting with a blank user
# XXX        password doesn't seem to work.
# XXX     2. LZW decompression doesn't work properly.
# XXX     3. Inline images are not handled at all.

import os
import re
import sys
import glob
import logging
import binascii
import tempfile
import subprocess

try:
    import cStringIO as StringIO
except ImportError:
    import StringIO

from PIL import Image

try:
    import pyPdf
    import pyPdf.pdf
    import pyPdf.filters
    import pyPdf.generic
except ImportError:
    pyPdf = None

import spambayes.Options
import spambayes.sb_logging
import spambayes.ImageStripper

spambayes.sb_logging.setup()
logger = logging.getLogger('spambayes')

def parts(walk):
    """Message parts that are able to be handled by this module."""
    for part in walk():
        if part.get_content_maintype() == "application" and \
           part.get_content_subtype() in ("pdf", "ps"):
            yield part

class MissingExecutable(RuntimeError):
    pass

def get_image_handler():
    options = spambayes.Options.options
    default = options["Tokenizer", 'x-ocr_engine']
    engine = spambayes.ImageStripper.get_engine(default, options)
    if not engine:
        logger.error("Invalid OCR engine: %s" % (default,))
        return
    image_handler = spambayes.ImageStripper.ImageStripper(options=options)
    image_handler.engine = engine
    return image_handler

def pdf_to_image_gs(parts):
    """Convert a bunch of PDFs or postscript files to images via
    Ghostscript.

    This method has the advantage that the resulting image is
    (theoretically) exactly what the user would see, and ghostscript is good
    at handling all sorts of problems with PDFs.  The main problem is that
    converting a PDF to an image is slow and results in very large (many
    hundreds of MB in many cases) images, which in turn slows down the OCR
    software.
    """
    options = spambayes.Options.options
    image_handler = get_image_handler()
    if not image_handler:
        return
    # XXX It would be nice if this could be automated in some way.
    if image_handler.engine.image_format.lower() == "tiff":
        # We could use tiff12nc, tiff24nc, tiff32nc, tiffcrle, tiffg3,
        # tiffg32d, tiffg4, tiffgray, tifflzw, tiffpack, or tiffsep.
        # We're not interested in colour, so tiffgray sounds the best.
        format = "tiffgray"
    else:
        # This will handle pnm, ppm, etc.
        format = image_handler.engine.image_format.lower() + "raw"
    if sys.platform == "win32":
        gs = spambayes.ImageStripper.find_program("gswin32c")
    else:
        gs = spambayes.ImageStripper.find_program("gs")
    if not gs:
        raise MissingExecutable()
    papersize = options["Tokenizer"]["x-pdf_to_image_paper_size"]
    resolution = options["Tokenizer"]["x-pdf_to_image_resolution"]
    last_page = options["Tokenizer"]["x-pdf_to_image_max_pages"]
    max_pixels = options["Tokenizer"]["x-pdf_to_image_max_pixels"]
    for part in parts:
        fd, image = tempfile.mkstemp('-%s-spambayes-image' % (os.getpid(),))
        os.close(fd)
        logger.debug("Creating temporary pdf image file: %s" % (image,))
        convert_cmd = '%s -sPAPERSIZE=%s -sDEVICE=%s -r%s -dNOPAUSE ' \
                      '-dSAFER -dBATCH -sOutputFile="%s" -dLastPage=%s ' \
                      '-q -' % (gs, papersize, format, resolution, image,
                                last_page)
        ghostscript = subprocess.Popen(convert_cmd, shell=True,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE,
                                       stdin=subprocess.PIPE)
        errors = ""
        try:
            ghostscript.stdin.write(part.get_payload(decode=True))
            ghostscript.stdin.close()
            errors = ghostscript.stderr.read()
            ghostscript.stdout.close()
            ghostscript.stderr.close()
        except Exception, e:
            # Ensure that ghostscript is closed.
            try:
                os.kill(ghostscript.pid, 9)
            except OSError:
                logger.error("Couldn't kill ghostscript")
            logger.error("Error in ghostscript: %s" % (e,))
        if errors:
            yield "invalid-image:%s" % part.get_content_subtype()
        if os.path.exists(image):
            # It's possible to have errors/warnings, and still have an
            # image that is worth processing.
            scale_cmd = spambayes.ImageStripper.find_program("pnmscale")
            if scale_cmd:
                fd, image2 = tempfile.mkstemp('-%s-spambayes-image' %
                                              (os.getpid(),))
                os.close(fd)
                logger.debug("Creating temporary resized pdf image file: %s"
                             % (image2,))
                scale = subprocess.Popen("%s -pixels %s -nomix %s" %
                                         (scale_cmd, max_pixels, image),
                                         shell=True, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE,
                                         stdin=subprocess.PIPE)
                try:
                    scaled = open(image2, "wb")
                    scaled.write(scale.stdout.read())
                    scaled.close()
                    scale.stdout.close()
                    scale.stderr.close()
                    scale.stdin.close()
                except Exception, e:
                    # Ensure that pnmscale is closed.
                    try:
                        os.kill(scale.pid, 9)
                    except OSError:
                        logger.error("Couldn't kill pnmscale")
                    logger.error("Error in pnmscale: %s" % (e,))
                logger.debug("Removing pre-pnmscale image: %s" % (image,))
                try:
                    os.remove(image)
                except OSError, e:
                    logger.error("Unable to remove image file: %s" % (e,))
                image = image2
            im = Image.open(image)
            im.load()
            for token in image_handler.extract_ocr_info(im):
                yield token
            logger.debug("Removing image: %s" % (image,))
            try:
                os.remove(image)
            except OSError:
                logger.warning("Couldn't remove image: %s" % (image,))

def pdf_to_image_xpdf(parts):
    """Convert a bunch of PDFs or postscript files to images via xpdf.

    This is more-or-less the same as pdf_to_image_gs (above), but uses xpdf
    instead (which has a smaller Windows executable, more suitable for
    redistribution.
    """
    options = spambayes.Options.options
    image_handler = get_image_handler()
    if not image_handler:
        return
    # XXX xpdf can only create PPMs, so if something else is requested,
    # XXX we'll have to convert it.
    xpdf = spambayes.ImageStripper.find_program("pdftoppm")
    if not xpdf:
        raise MissingExecutable()
    last_page = options["Tokenizer"]["x-pdf_to_image_max_pages"]
    resolution = options["Tokenizer"]["x-pdf_to_image_resolution"]
    for part in parts:
        fd, image = tempfile.mkstemp('-spambayes-image')
        os.close(fd)
        logger.debug("Creating temporary pdf image file: %s" % (image,))
        # Save pdf to temp location (we need an actual file for xpdf).
        fd, pdf = tempfile.mkstemp('-spambayes-pdf')
        logger.debug("Creating temporary pdf file: %s" % (pdf,))
        os.write(fd, part.get_payload(decode=True))
        os.close(fd)
        convert_cmd = '%s -gray -r %s -l %s "%s" "%s"' % \
                      (xpdf, resolution, last_page, pdf, image)
        xpdf_process = subprocess.Popen(convert_cmd, shell=True,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE,
                                        stdin=subprocess.PIPE)
        try:
            errors = xpdf_process.stderr.read()
        except Exception, e:
            # Ensure that xpdf is closed.
            try:
                os.kill(xpdf_process.pid, 9)
            except OSError:
                logger.error("Couldn't kill xpdf")
            logger.error("Error in xpdf: %s" + (e,))
        xpdf_process.stdin.close()
        xpdf_process.stdout.close()
        xpdf_process.stderr.close()
        if errors:
            yield "invalid-image:%s" % part.get_content_subtype()
        # Remove the PDF.
        try:
            os.remove(pdf)
        except OSError:
            logger.error("Couldn't remove temporary PDF: %s" % (pdf,))
        images = glob.glob(image + "*")
        for image in images:
            im = Image.open(image)
            im.load()
            for token in image_handler.extract_ocr_info(im):
                yield token
            logger.debug("Removing image: %s" % (image,))
            try:
                os.remove(image)
            except OSError:
                logger.warning("Couldn't remove image: %s" % (image,))

def int2bin(n, count=24):
    """Returns the binary of integer n, using count number of digits."""
    return "".join([str((n >> y) & 1) for y in xrange(count-1, -1, -1)])

def _lzw_decompress(compressed):
    # This assumes that the code length (number of dictionary entries) will
    # never get higher than 2**9 (512).
    b = "".join([int2bin(ord(c), 8) for c in compressed])
    bytes = [int(b[i*9:(i+1)*9], 2) for i in xrange(len(compressed)/9)]
    if bytes[0] == 256:
        bytes = bytes[1:]
    d = [chr(i) for i in xrange(256)] + [None, None]
    w = bytes[0]
    for k in bytes:
        if k == 256:
            # Clear table.
            d = [chr(i) for i in xrange(256)] + [None, None]
        elif k == 257:
            # EOD.  Remaining bits of the byte are set to 0.
            print "EOD"
            return
        else:
            entry = d[k]
            for c in entry:
                yield c
            d.append(d[w] + entry)
            w = k
lzw_decompress = lambda c : "".join(_lzw_decompress(c))

class LZWDecode(object):
    def decode(data, decodeParms):
        data = lzw_decompress(data)
        predictor = 1
        if decodeParms:
            predictor = decodeParms.get("/Predictor", 1)
        # predictor 1 == no predictor
        if predictor != 1:
            columns = decodeParms["/Columns"]
            # PNG prediction:
            if predictor >= 10 and predictor <= 15:
                output = StringIO()
                # PNG prediction can vary from row to row
                rowlength = columns + 1
                assert len(data) % rowlength == 0
                prev_rowdata = (0,) * rowlength
                for row in xrange(len(data) / rowlength):
                    rowdata = [ord(x) for x in data[(row*rowlength):((row+1)*rowlength)]]
                    filterByte = rowdata[0]
                    if filterByte == 0:
                        pass
                    elif filterByte == 1:
                        for i in range(2, rowlength):
                            rowdata[i] = (rowdata[i] + rowdata[i-1]) % 256
                    elif filterByte == 2:
                        for i in range(1, rowlength):
                            rowdata[i] = (rowdata[i] + prev_rowdata[i]) % 256
                    else:
                        # unsupported PNG filter
                        raise pyPdf.PdfReadError("Unsupported PNG filter %r" % filterByte)
                    prev_rowdata = rowdata
                    output.write(''.join([chr(x) for x in rowdata[1:]]))
                data = output.getvalue()
            else:
                # unsupported predictor
                raise pyPdf.PdfReadError("Unsupported lzwdecode predictor %r" % predictor)
        return data
    decode = staticmethod(decode)

    def encode(data):
        raise NotImplementedError()
    encode = staticmethod(encode)

def indexed_colourspace(bytes, space, maximum):
    new_bytes = []
    for byte in bytes:
        if ord(byte) > maximum:
            # Invalid index.  Wrap around, since there's no right answer.
            new_bytes.append(chr(ord(byte) % maximum))
        else:
            new_bytes.append(byte)
    return "".join([space[ord(byte)*3:(ord(byte)+1)*3]
                    for byte in new_bytes])

def icc_alternate(args):
    alternate = args.get("/Alternate")
    if not alternate:
        N = alternate["/N"]
        if N == 1:
            alternate = "/DeviceGray"
        elif N == 3:
            alternate = "/DeviceRGB"
        elif N == 4:
            alternate = "/DeviceCYMK"
        else:
            print "Unable to handle ICCBased:", args
            return None
    return alternate

def handle_colourspace(pdf, bytes, size, colourspace):
    #print len(bytes), len(bytes)*3
    if colourspace in ("/DeviceGray", "/DeviceRGB", "/DeviceCYMK"):
        return bytes, colourspace
    elif colourspace[0] == "/Indexed":
        if isinstance(colourspace[1], pyPdf.generic.IndirectObject):
            device = pdf.getObject(colourspace[1])
        else:
            device = colourspace[1]
        if device == "/DeviceRGB":
            if isinstance(colourspace[3], pyPdf.generic.IndirectObject):
                space = pdf.getObject(colourspace[3]).getData()
            else:
                space = colourspace[3]
            print len(space)
            bytes = indexed_colourspace(bytes, space, colourspace[2])
        elif device[0] == "/ICCBased":
            if isinstance(device[1], pyPdf.generic.IndirectObject):
                args = pdf.getObject(device[1])
            else:
                args = device[1]
            # XXX We do not know how to handle the ICC profile, so fall back
            # XXX to the alternate.
            alternate = icc_alternate(args)
            return handle_colourspace(pdf, bytes, size,
                                      (colourspace[0], alternate,
                                       colourspace[2], colourspace[3]))
        else:
            print "Can't handle device:", colourspace, device
            return bytes, colourspace[0]
    elif colourspace[0] == "/ICCBased":
        if isinstance(colourspace[1], pyPdf.generic.IndirectObject):
            profile = pdf.getObject(colourspace[1])
        else:
            profile = colourspace[1]
        icc = pyPdf.filters.decodeStreamData(profile)
        # XXX We do not know how to handle the ICC profile, so fall back
        # XXX to the alternate.
        alternate = icc_alternate(profile)
        if not alternate:
                return bytes, colourspace[0]
        return bytes, alternate
    else:
        print "Can't handle colour space:", colourspace
        return bytes, colourspace[0]
    #print len(bytes), size[0], size[1], 3 * size[0] * size[1], device, colourspace
    if len(bytes) != 3 * size[0] * size[1]:
        # Not enough data.  Seems that this must be a
        # bad file (although they seem to display ok).
        # Crop as best we can.
        if len(bytes) > size[1] * 3:
            size[0] = int(len(bytes) / 3 / size[1])
        elif len(bytes) > size[0] * 3:
            size[1] = int(len(bytes) / 3 / size[0])
        else:
            print "Not enough data"
    return bytes, colourspace[0]

def handle_xobject(pdf, obj, name):
    if obj["/Subtype"] != "/Image":
        return
    # /DCTDecode is not supported by pyPdf, but PIL can handle it raw, so
    # we can pretend it's not filtered.
    if obj.get("/Filter") == "/DCTDecode":
        del obj["/Filter"]
    # If the filter is a list of one object, replace it with just that
    # object.
    if isinstance(obj.get("/Filter"), list) and len(obj["/Filter"]) == 1:
        key = pyPdf.generic.createStringObject("/Filter")
        value = pyPdf.generic.createStringObject(obj["/Filter"][0])
        obj[key] = value
    try:
        bytes = obj.getData()
        return
    except AttributeError:
        bytes = obj._data
        return
    except AssertionError:
        if obj["/Filter"] == "/LZWDecode":
            print obj
            bytes = LZWDecode.decode(obj._data, obj.get("/DecodeParms"))
        else:
            # Try the raw data.
            bytes = obj._data
            return
    size = [obj["/Width"], obj["/Height"]]
    bytes, colourspace = handle_colourspace(pdf, bytes, size, obj["/ColorSpace"])
    print size, len(bytes), size[0] * size[1] * 3
    if colourspace == "/DeviceRGB":
        return Image.open(StringIO.StringIO(bytes))
    elif colourspace == "/DeviceGray":
        return Image.open(StringIO.StringIO(bytes))
    return Image.frombuffer("RGB", size, bytes, "raw", "RGB", 0, 1)

def fix_xrefs(raw_pdf):
    # If the PDF has a bad position for the xref table, we get a
    # TypeError.  Fix it manually.  We also need to regenerate the xref
    # table.
    raw_pdf.seek(0)
    pdf_data = raw_pdf.read()
    pdf_data = re.sub(r"startxref\n\d+\n%%EOF",
                      "startxref\n%d\n%%%%EOF" % (pdf_data.find("xref"),),
                      pdf_data)
    xrefs = {}
    start = 0
    while True:
        mo = re.search(r"(\d+) \d+ obj\n", pdf_data[start:])
        if not mo:
            break
        xrefs[int(mo.group(1))] = start + mo.start()
        start += mo.end()
    pdf_data = "%s\nxref\n0 %d\n0000000000 65535 f \n%s\n%s" % \
               (pdf_data[:pdf_data.find("xref")], len(xrefs)+1,
                "\n".join(["%.10d 00000 n " % (xrefs[obj],)
                           for obj in sorted(xrefs.keys())]),
                pdf_data[pdf_data.find("trailer"):])
    return pyPdf.PdfFileReader(StringIO.StringIO(pdf_data))

def tokenize(parts):
    options = spambayes.Options.options
    if options["Tokenizer", "x-crack_pdfs"]:
        if not pyPdf:
            # This option should only be enabled if pyPdf is available.
            logger.critical("pyPdf module is not available")
            return
        for part in parts:
            try:
                raw_pdf = part.get_payload(decode=True)
            except binascii.Error, e:
                logger.warn("Unable to decode part: %s", e)
                yield "pdf:exception"
                continue
            # Apparently the first 100 bytes is a reasonable clue (many use
            # the same initial commands, which are different than legitimate
            # PDFs).
            yield raw_pdf[:100]
            # Now parse the PDF file and generate tokens from what we find.
            try:
                for token in tokenize_pdf(StringIO.StringIO(raw_pdf)):
                    yield token
            except Exception:
                yield "pdf:exception"
    if options["Tokenizer", "x-pdf_to_image"]:
        # Try ghostscript first, and fall back to xpdf.
        try:
            for token in pdf_to_image_gs(parts, format="PPM"):
                yield token
        except MissingExecutable:
            try:
                for token in pdf_to_image_xpdf(parts):
                    yield token
            except MissingExecutable:
                # This option should only be enabled if either ghostscript
                # or xpdf is available.
                logger.critical("No PDF converter available")

class UnexpectedEndOfData(Exception):
    pass

if pyPdf:
    class CorrectedPdfFileReader(pyPdf.PdfFileReader):
        def readNextEndLine(self, stream):
            # Go backwards through the file, and return the first line
            # found. If a line is not found, raise an error.
            # Use absolute positions for clarity, and avoid any loops
            # without definite endings.
            start = stream.tell()
            line = []
            for pos in xrange(start, -1, -1):
                stream.seek(pos)
                x = stream.read(1)
                if not x:
                    raise UnexpectedEndOfData()
                if x in ('\r', '\n'):
                    # Skip back past any newline characters.
                    for skip_pos in xrange(pos, -1, -1):
                        stream.seek(pos)
                        x = stream.read(1)
                        if not x:
                            raise UnexpectedEndOfData()
                        if x not in ('\r', '\n'):
                            break
                    break
                line.append(x)
            return "".join(reversed(line))

def tokenize_pdf(file_obj):
    # Late import to avoid any circular dependancies.
    import spambayes.tokenizer
    try:
        pdf = CorrectedPdfFileReader(file_obj)
    except (TypeError, ValueError):
        yield "pdf-broken-xrefs"
        # We used to try and fix the xrefs, but particular PDFs could get
        # caught in an infinite loop (c.f. SE ticket #5039).  For now, just
        # leave as broken.
        return
        pdf = fix_xrefs(file_obj)
    except UnexpectedEndOfData:
        yield "pdf:invalid"
        return
    except Exception, e:
        logger.info("Unknown problem with PDF extraction: %s", e)
        yield "pdf:error"
        # XXX Examples of this problem can be found in #3213.
#        file_obj.seek(0)
#        with open("/tmp/%s.pdf" %
#                  (datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S"),),
#                  "wb") as crash_pdf:
#            crash_pdf.write(file_obj.read())
        return
    if pdf.isEncrypted:
        yield "pdf-encrypted:True"
        decrypt_type = pdf.decrypt("")
        yield "pdf-decrypt-type:%s" % (decrypt_type,)
        if not decrypt_type:
            logger.error("Could not decrypt PDF")
            return
    else:
        return
        yield "pdf-encrypted:False"
    info = pdf.documentInfo
    yield "pdf-author:%s" % (info.author,)
    yield "pdf-creator:%s" % (info.creator,)
    yield "pdf-producer:%s" % (info.producer,)
    yield "pdf-subject:%s" % (info.subject,)
    yield "pdf-title:%s" % (info.title,)
    options = spambayes.Options.options
    tokenize_text = spambayes.tokenizer.Tokenizer(options).tokenize_text
    image_handler = get_image_handler()
    if not image_handler:
        return
    for page in pdf.pages:
        # XXX Apparently the /Charset would also be a good clue.
        for token in tokenize_text(page.extractText().strip()):
            yield token
        for attribute in ("mediaBox", "cropBox", "bleedBox", "trimBox",
                          "artBox"):
            try:
                box = getattr(page, attribute)
            except TypeError:
                yield "pdf-no-" + attribute
            else:
                for x in "left", "right":
                    for y in "lower", "upper":
                        yield "pdf-%s-%s-%s-x:%s" % \
                              (attribute, y, x,
                               getattr(box, y + x.title())[0])
                        yield "pdf-%s-%s-%s-y:%s" % \
                              (attribute, y, x,
                               getattr(box, y + x.title())[1])
        content = page["/Contents"].getObject()
        if not isinstance(content, pyPdf.pdf.ContentStream):
            content = pyPdf.pdf.ContentStream(content, page.pdf)
        handled_xobjects = []
        for operands, operator in content.operations:
            if operator == "Do":
                name = operands[0]
                if name in handled_xobjects:
                    continue
                handled_xobjects.append(name)
                im = handle_xobject(pdf, page["/Resources"]["/XObject"]
                                    [name], name)
                if not im:
                    continue
                im.load()
                import time
                im.save("/Users/tameyer/Desktop/test/%s.jpg" % (int(time.time()),))
                time.sleep(1)
                for token in image_handler.extract_ocr_info(im):
                    yield token
            elif operator == "BI":
                logger.info("PDF contains inline image object (start)")
            elif operator == "ID":
                logger.info("PDF contains inline image object (data)")
            elif operator == "EI":
                logger.info("PDF contains inline image object (end)")

class dummy_part(object):
    def __init__(self, filename):
        self.filename = filename
    def get_payload(self, decode=True):
        return open(self.filename, "rb").read()
class SlurpingPDFStripper(spambayes.ImageStripper.SlurpingImageStripper):
    def tokenize(self, m):
        proto, url = m.groups()
        if proto != "http":
            return []
        while url and url[-1] in '.:;?!/)':
            url = url[:-1]
        tokens = []
        result = self.retrieve_file(proto, url, tokens, (".pdf", ".ps"))
        if result is None:
            return tokens
        content_type, content = result
        # Anything that isn't a PDF or PS document is ignored.
        is_pdf = content_type.startswith("application/pdf") or \
                 content_type.startswith("application/ps")
        if not content_type or not is_pdf:
            tokens.append("url:non_image")
            return tokens
        tokens.extend(tokenize(dummy_part(content)))
        return tokens

options = spambayes.Options.options
crack_urls_slurp_pdf = SlurpingPDFStripper(options).analyze
del options
