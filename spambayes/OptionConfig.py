"""Options Configurator
Classes:
    OptionsConfigurator - changes select values in Options.py

Abstract:

This module implements a browser based Spambayes option file configuration
utility.  Users may use the pages in this application to customize the
options in the bayescustomize.ini file.

This does not support the BAYESCUSTOMIZE environment variable.  Is this even
used anywhere?

By default, this module forms a part of the web user interface provided by
pop3proxy.py.  You can also run it standalone, but only for historical
reasons.  To do this, just invoke OptionConfig.py <optional port number>
The port number is the port the http server will listen on, and defaults to
8000.  Your web browser should launch automatically; if it doesn't, then
point it to http://locahost:8000 (or whatever port you chose).

To Do:
    o Suggestions?

"""

# This module is part of the spambayes project, which is Copyright 2002
# The Python Software Foundation and is covered by the Python Software
# Foundation license.

__author__ = "Tim Stone <tim@fourstonesExpressions.com>"
# Blame for bugs caused by using Dibbler: Richie Hindle <richie@entrian.com>


from spambayes import Dibbler, PyMeldLite
from spambayes.Options import options
import re
import os, sys
import ConfigParser
import copy

IMAGES = ('helmet', 'config', 'status')

# This control dictionary maps http request parameters and template fields
# to ConfigParser sections and options.  The key matches both the input
# field that corresponds to a section/option, and also the HTML template
# variable that is used to display the value of that section/option.
parm_ini_map = \
   {'hamcutoff':    ('Categorization',  'ham_cutoff'),
    'spamcutoff':   ('Categorization',  'spam_cutoff'),
    'dbname':       ('pop3proxy',       'pop3proxy_persistent_storage_file'),
    'headername':   ('Hammie',          'hammie_header_name'),
    'spamstring':   ('Hammie',          'header_spam_string'),
    'hamstring':    ('Hammie',          'header_ham_string'),
    'unsurestring': ('Hammie',          'header_unsure_string'),
    'p3servers':    ('pop3proxy',       'pop3proxy_servers'),
    'p3ports':      ('pop3proxy',       'pop3proxy_ports'),
   }

# "Restore defaults" ignores these, because it would be pointlessly
# destructive - they default to being empty, so you gain nothing by
# restoring them.
noRestore = ('pop3proxy_servers', 'pop3proxy_ports')

# This governs the order in which the options appear on the configurator
# page, and the headings and help text that are used.
page_layout = \
(
    ("POP3 Options",
    (   ("p3servers", "Servers",
         """The Spambayes POP3 proxy intercepts incoming email and classifies
         it before sending it on to your email client.  You need to specify
         which POP3 server(s) you wish it to intercept - a POP3 server
         address typically looks like "pop3.myisp.net".  If you use more than
         one server, simply separate their names with commas.  You can get
         these server names from your existing email configuration, or from
         your ISP or system administrator.  If you are using Web-based email,
         you can't use the Spambayes POP3 proxy (sorry!).  In your email
         client's configuration, where you would normally put your POP3 server
         address, you should now put the address of the machine running
         Spambayes."""),

        ("p3ports", "Ports",
         """Each POP3 server that is being monitored must be assigned to a
         'port' in the Spambayes POP3 proxy.  This port must be different for
         each monitored server, and there MUST be a port for each monitored
         server.  Again, you need to configure your email client to use this
         port.  If there are multiple servers, you must specify the same
         number of ports as servers, separated by commas."""),
    )),

    ("Statistics Options",
    (   ("hamcutoff", "Ham Cutoff",
         """Spambayes gives each email message a spam probability between
         0 and 1. Emails below the Ham Cutoff probability are classified
         as Ham. Larger values will result in more messages being
         classified as ham, but with less certainty that all of them
         actually <i>are</i> ham. This value should be between 0 and 1,
         and should be smaller than the Spam Cutoff."""),

        ("spamcutoff", "Spam Cutoff",
         """Emails with a spam probability above the Spam Cutoff are
         classified as Spam - just like the Ham Cutoff but at the other
         end of the scale.  Messages that fall between the two values
         are classified as Unsure."""),

        ("dbname", "Database filename",
         """Spambayes builds a database of information that it gathers
         from incoming emails and from you, the user, to get better and
         better at classifying your email.  This option specifies the
         name of the database file.  If you don't give a full pathname,
         the name will be taken to be relative to the current working
         directory."""),
    )),
)

# Tim Stone's original OptionConfig.py had these options as well, but I
# (Richie) suggested that they were overkill, and Tim agreed.  We can always
# put them back if people want them.
_insertedHeaderOptions = '''
    ("Inserted Header Options",
    (   ("headername", "Header Name",
         """Spambayes classifies each message by inserting a new header into
         the message.  This header can then be used by your email client
         (provided your client supports filtering) to move spam into a
         separate folder (recommended), delete it (not recommended), etc.
         This option specifies the name of the header that Spambayes inserts.
         The default value should work just fine, but you may change it to
         anything that you wish."""),

        ("spamstring", "Spam Designation",
         """The header that Spambayes inserts into each email has a name,
            (Header Name, above), and a value.  If the classifier determines
            that this email is probably spam, it places a header named as
            above with a value as specified by this string.  The default
            value should work just fine, but you may change it to anything
            that you wish."""),

        ("hamstring", "Ham Designation",
         """As for Spam Designation above, but for emails classified as
         Ham."""),

        ("unsurestring", "Unsure Designation",
         """As for Spam/Ham Designation above, but for emails which the
         classifer wasn't sure about (ie. the spam probability fell between
         the Ham and Spam Cutoffs).  Emails that have this classification
         should always be the subject of training."""),
    )),
'''

OK_MESSAGE = "%s.  Return <a href='home'>Home</a>."

PIMapSect = 0
PIMapOpt = 1


class OptionsConfigurator(Dibbler.HTTPPlugin):
    def __init__(self, proxyUI=None):
        Dibbler.HTTPPlugin.__init__(self)

        # Store the proxy UI; this won't be given when we're standalone.
        self.proxyUI = proxyUI

        # Load up the necessary resources: ui.html and the GIFs.
        from pop3proxy import readUIResources
        htmlSource, self._images = readUIResources()
        self.html = PyMeldLite.Meld(htmlSource)

        # Adjust the HTML according to whether we're running standalone or as
        # a part of the proxy.
        if not self.proxyUI:
            self.html.productName = "Spambayes Options Configurator"
            self.html.footerHome = "Spambayes Options Configurator"
            self.html.shutdownButton.value = "Shutdown Configurator"
        else:
            # "Save and Shutdown" is confusing here - it means "Save database"
            # but that's not clear.
            self.html.shutdownTableCell = "&nbsp;"

    def onConfig(self):
        # start with the options config file, add bayescustomize.ini to it
        bcini = ConfigParser.ConfigParser()

        # this is a pain...
        for sect in options._config.sections():
            for opt in options._config.options(sect):
                try:
                    bcini.set(sect, opt, options._config.get(sect, opt))
                except ConfigParser.NoSectionError:
                    bcini.add_section(sect)
                    bcini.set(sect, opt, options._config.get(sect, opt))

        bcini.read('bayescustomize.ini')

        # Start with an empty config form then add the sections.
        html = self.html.clone()
        html.mainContent = self.html.configForm.clone()
        html.mainContent.configFormContent = ""

        # Loop though the sections in the `page_layout` structure above.
        for sectionHeading, values in page_layout:
            # Start the yellow-headed box for this section.
            section = self.html.headedBox.clone()
            section.heading = sectionHeading
            del section.iconCell

            # Get a clone of the config table and a clone of each example row,
            # then blank out the example rows to make way for the real ones.
            configTable = self.html.configTable.clone()
            configRow1 = configTable.configRow1.clone()
            configRow2 = configTable.configRow2.clone()
            blankRow = configTable.blankRow.clone()
            del configTable.configRow1
            del configTable.configRow2
            del configTable.blankRow

            # Now within this section, loop though the values, adding a
            # labelled input control for each one, populated with the current
            # value.
            isFirstRow = True
            for name, label, unusedHelp in values:
                newConfigRow1 = configRow1.clone()
                newConfigRow2 = configRow2.clone()
                currentValue = bcini.get(parm_ini_map[name][PIMapSect], \
                                         parm_ini_map[name][PIMapOpt])

                # If this is the first row, insert the help text in a cell
                # with a `rowspan` that covers all the rows.
                if isFirstRow:
                    entries = []
                    for unusedName, topic, help in values:
                        entries.append("<p><b>%s: </b>%s</p>" % (topic, help))
                    newConfigRow1.helpSpacer = '&nbsp;' * 10
                    newConfigRow1.helpCell = '\n'.join(entries)
                else:
                    del newConfigRow1.helpSpacer
                    del newConfigRow1.helpCell

                # Populate the rows with the details and add them to the table.
                newConfigRow1.label = label
                newConfigRow1.input.name = name
                newConfigRow1.input.value = currentValue
                newConfigRow2.currentValue = currentValue
                configTable += newConfigRow1 + newConfigRow2 + blankRow
                isFirstRow = False

            # Finish off the box for this section and add it to the form.
            section.boxContent = configTable
            html.configFormContent += section

        # Customise the page according to whether we're standalone or a proxy.
        if self.proxyUI:
            html.title = 'Home &gt; Configure'
            html.pagename = '&gt; Configure'
        else:
            html.title = 'Home'
            del html.homelink
            html.pagename = 'Home'

        self.writeOKHeaders('text/html')
        self.write(html)

    # Implement `onHome` for the standalone version.  In the POP3 proxy, the
    # proxy UI's `onHome` will take precedence over this one.
    onHome = onConfig

    def onChangeopts(self, **parms):
        html = self.html.clone()
        html.mainContent = self.html.headedBox.clone()
        errmsg = editInput(parms)
        if errmsg != '':
            html.mainContent.heading = "Errors Detected"
            html.mainContent.boxContent = errmsg
            html.title = 'Home &gt; Error'
            html.pagename = '&gt; Error'
            self.writeOKHeaders('text/html')
            self.write(html)
            return

        updateIniFile(parms)

        html.mainContent.heading = "Options Changed"
        if self.proxyUI:
            html.mainContent.boxContent = OK_MESSAGE % "Options changed"
            self.proxyUI.reReadOptions()
        else:
            html.mainContent.boxContent = """The options changes you've made
                   have been recorded.  You will need to restart any Spambayes
                   processes you have running, such as the pop3proxy, in order
                   for your changes to take effect.  When you return to the
                   Options Configuration homepage, you may need to refresh the
                   page to see the changes you have made."""
        html.title = 'Home &gt; Options Changed'
        html.pagename = '&gt; Options Changed'
        self.writeOKHeaders('text/html')
        self.write(html)

    def onRestoredefaults(self, how):
        restoreIniDefaults()
        html = self.html.clone()
        html.mainContent = self.html.headedBox.clone()
        html.mainContent.heading = "Option Defaults Restored"
        if self.proxyUI:
            html.mainContent.boxContent = OK_MESSAGE % "Defaults restored"
            self.proxyUI.reReadOptions()
        else:
            html.mainContent.boxContent = """All options have been reverted to
              their default values.  You will need to restart any Spambayes
              processes you have running, such as the pop3proxy, in order for
              your changes to take effect.  When you return to the Options
              Configuration homepage, you may need to refresh the page to see
              the changes you have made."""
        html.title = 'Home &gt; Defaults Restored'
        html.pagename = '&gt; Defaults Restored'
        self.writeOKHeaders('text/html')
        self.write(html)

    def onSave(self, how):
        # Really 'shutdown'; this is the button in the footer, not on the
        # form.  Again, the proxy UI's `onSave` will override this one when
        # we're running as part of the proxy.
        html = self.html.clone()
        del html.helmet
        del html.homelink
        html.shutdownTableCell = "&nbsp;"
        html.mainContent = self.html.shutdownMessage
        html.title = 'Home &gt; Shutdown'
        html.pagename = 'Shutdown'
        self.writeOKHeaders('text/html')
        self.write(html)
        self.close()
        sys.exit()

    def _writeImage(self, image):
        self.writeOKHeaders('image/gif')
        self.write(self._images[image])

    # If you are easily offended, look away now...
    for imageName in IMAGES:
        exec "def %s(self): self._writeImage('%s')" % \
             ("on%sGif" % imageName.capitalize(), imageName)


def editInput(parms):

    errmsg = ''

    # edit numericity of hamcutoff and spamcutoff
    try:
        hco = parms['hamcutoff']
    except KeyError:
        hco = options.ham_cutoff

    try:
        sco = parms['spamcutoff']
    except KeyError:
        sco = options.spam_cutoff

    errmsg = ''
    try:
        hco = float(hco)
    except ValueError:
        errmsg += '<li>Ham cutoff must be a number, between 0 and 1</li>\n'

    try:
        sco = float(sco)
    except ValueError:
        errmsg += '<li>Spam cutoff must be a number, \
between 0 and 1</li>\n'

    # edit 0 <= hamcutoff < spamcutoff <= 1
    if hco < 0 or hco > 1:
        errmsg += '<li>Ham cutoff must be between 0 and 1</li>\n'
    if sco < 0 or sco > 1:
        errmsg += '<li>Spam cutoff must be between 0 and 1</li>\n'
    if not hco < sco:
        errmsg += '<li>Ham cutoff must be less than Spam cutoff</li>\n'

    # edit for equal number of pop3servers and ports
    try:
        slist = parms['p3servers'].split(',')
    except KeyError:
        slist = options.pop3proxy_servers.split(',')

    try:
        plist = parms['p3ports'].split(',')
    except KeyError:
        plist = options.pop3proxy_ports.split(',')

    # edit for duplicate ports
    if len(slist) != len(plist):
        errmsg += '<li>The number of ports specified must match the \
number of servers specified</li>\n'

    plist.sort()
    for p in range(len(plist)-1):
        try:
            if plist[p] == plist[p+1]:
                errmsg += '<li>All port numbers must be unique</li>'
                break
        except IndexError:
            pass

    return errmsg

def updateIniFile(parms):

    # assumes bayescustomize.ini is in this process' working directory

    inipath = os.path.abspath('bayescustomize.ini')

    bcini = ConfigParser.ConfigParser()
    bcini.read(inipath)

    for httpParm in parm_ini_map:
        map = parm_ini_map[httpParm]
        sect = map[PIMapSect]
        opt = map[PIMapOpt]

        try:
            val = parms[httpParm]
        except KeyError:
            continue

        try:
            bcini.add_section(sect)
        except ConfigParser.DuplicateSectionError:
            pass

        bcini.set(sect, opt, val)

    o = open(inipath, 'wt')
    bcini.write(o)
    o.close()

def restoreIniDefaults():

    # assumes bayescustomize.ini is in this process' working directory

    inipath = os.path.abspath('bayescustomize.ini')

    bcini = ConfigParser.ConfigParser()
    bcini.read(inipath)

    # Only restore the settings that appear on the form.
    for section, option in parm_ini_map.values():
        if option not in noRestore:
            try:
                bcini.remove_option(section, option)
            except ConfigParser.NoSectionError:
                pass    # Already missing.

    o = open(inipath, 'wt')
    bcini.write(o)
    o.close()


def run(port):
    httpServer = Dibbler.HTTPServer(port)
    httpServer.register(OptionsConfigurator())
    Dibbler.run(launchBrowser=True)

if __name__ == '__main__':
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    else:
        port = 8000
    run(port)
