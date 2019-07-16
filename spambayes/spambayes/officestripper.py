import os
import time
import zlib
import struct
import zipfile
import logging
import tempfile
import subprocess

# This previously used OpenOffice to convert documents (Word and OpenOffice
# word processing, spreadsheet, and presentation) to PDF, and then used the
# existing PDF-to-text code to get the resulting text.  That worked, with
# some problems:
#     * OpenOffice takes a lot of resources.  This is even more so because
#       as far as I can tell, it is only possible to run it with a display,
#       so a virtual frame buffer must also be setup.  If there was a simple
#       command-line 'convert' tool, it would be more practical.
#     * It's not entirely clear how well OpenOffice deals with multiple
#       simultaneous connections.  Information online is sketchy, but it
#       does seem like these are not handled well.
#     * Going through PDF is much less efficient, even though we directly
#       parse the PDF, than simply going directly to text.
#
# There are some advantages:
#     * This is a widely used, well supported, program.  The developers have
#       the resources to get conversion correct.
#     * A lot of formats are handled.
#     * We get any images that are in the documents (so an image inside of
#       a word document, for example, does generate tokens), and these are
#       automatically handled in the same way that any other images in PDFs
#       are handled.
#
# In general, spam in Office documents seemed to be a short-lived fad.  My
# suspicion is that we generally manage to handle these messages without
# any tokens.  Combined with the resource requirements, this has led me to
# removing the OpenOffice code (I have it if anyone wants it) in favour of
# using the 'antiword' tool.  This requires few resources, and doesn't
# require going through PDF.  It doesn't handle images or non-Word
# docuemnts, however.
#
# In general, the best solution, now that full documentation on the formats
# is available, would be a native parser that could read these formats and
# yield any text or images included.  However, that would be a mammoth task,
# and the benefits are too slim to do as part of this.  In addition, it is
# likely that the use of .doc/.xls/.ppt will decrease, and .docx (etc) will
# increase, and those are much more easily parsed.
#
# Later: there's now a Python module (docx) available for working with the
# docx format.  We use that for docx, and antiword for doc.

import lxml.etree

import docx

import spambayes.Options
import spambayes.sb_logging

spambayes.sb_logging.setup()
logger = logging.getLogger('spambayes')

# MIME types that Antiword can handle.
office_subtypes = (
    "vnd.ms-word", "msword",
    "vnd.openxmlformats-officedocument.wordprocessingml.document",
    )

TOKEN_LIMIT = 1000


def parts(walk):
    """Message parts that are able to be handled by this module."""
    for part in walk():
        if part.get_content_maintype() == "application" and \
           part.get_content_subtype() in office_subtypes:
            yield part


def tokenize(parts):
    """Convert Microsoft Office documents into tokens."""
    # Late import to avoid any circular dependancies.
    import spambayes.tokenizer
    tok = spambayes.tokenizer.Tokenizer
    tokenize_text = tok(spambayes.Options.options).tokenize_text
    for part in parts:
        if (part.get_content_subtype() ==
            "vnd.openxmlformats-officedocument.wordprocessingml.document"):
            func = tokenize_docx
        else:
            func = tokenize_doc
        for token in func(part, tokenize_text):
            yield token


def tokenize_doc(part, tokenize_text):
    """Convert .doc into tokens."""
    # antiword requires an actual file.
    attachment = os.path.join(tempfile.gettempdir(), "%s-%s.doc" %
                              (os.getpid(), time.time()))

    data = open(attachment, "wb")
    try:
        data.write(part.get_payload(decode=True))
        data.close()
        antiword = subprocess.Popen(["/usr/bin/antiword", attachment],
                                    stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
        stdout, stderr = antiword.communicate()
        token_count = 0
        for token in tokenize_text(stdout):
            yield token
            token_count += 1
            if token_count > TOKEN_LIMIT:
                break
        for token in tokenize_text(stderr):
            yield token
            token_count += 1
            if token_count > TOKEN_LIMIT:
                break
    finally:
        os.remove(attachment)


def tokenize_docx(part, tokenize_text):
    """Convert .docx into tokens."""
    # docx requires an actual file.
    attachment = os.path.join(tempfile.gettempdir(), "%s-%s.docx" %
                              (os.getpid(), time.time()))
    data_file = open(attachment, "wb")
    data_file.write(part.get_payload(decode=True))
    data_file.close()
    try:
        try:
            document = docx.opendocx(attachment)
        except struct.error:
            yield "docx:struct_error"
        except (zipfile.BadZipfile, zipfile.error, zlib.error):
            yield "docx:bad_zip"
        except (KeyError, lxml.etree.XMLSyntaxError, IOError):
            yield "docx:bad_document"
        else:
            token_count = 0
            for paragraph in docx.getdocumenttext(document):
                for token in tokenize_text(paragraph):
                    yield token
                    token_count += 1
                    if token_count > TOKEN_LIMIT:
                        break
                if token_count > TOKEN_LIMIT:
                    break
    finally:
        os.remove(attachment)


class dummy_part(object):
    def __init__(self, filename):
        self.filename = filename

    def get_payload(self, decode=True):
        return open(self.filename, "rb").read()


class SlurpingOfficeStripper(spambayes.ImageStripper.SlurpingImageStripper):
    def tokenize(self, m):
        proto, url = m.groups()
        if proto != "http":
            return []
        while url and url[-1] in '.:;?!/)':
            url = url[:-1]
        exts = (".doc", )
        tokens = []
        result = self.retrieve_file(proto, url, tokens, exts)
        if result is None:
            return tokens
        content_type, content = result
        # Anything that isn't an office document is ignored.
        is_office = False
        if content_type.startswith("application"):
            for subtype in office_subtypes:
                if content_type[12:].startswith(subtype):
                    is_office = True
                    break
        if not content_type or not is_office:
            tokens.append("url:non_image")
            return tokens
        tokens.extend(tokenize(dummy_part(content)))
        return tokens

options = spambayes.Options.options
crack_urls_slurp_office = SlurpingOfficeStripper(options).analyze
del options
