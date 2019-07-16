"""dnscache.py

This is a rewrite of the standard spambayes.dnscache module (created by
Matthew Dixon Cowles).  The original module uses the PyDNS package, and this
re-write uses the python-dns package (annoyingly, one module is imported
as "DNS" and one as "dns").

The point of the module is to provide a simple interface for DNS queries
that handles timeouts and caching appropriately for lookups during
tokenizing.

The original spambayes.dnscache module saved a cache of the lookups in a
pickle on disk.  The main problem with this is that it is not thread (or
process) safe - if there are multiple tokenizers running concurrently, then
they will clash when reading/writing the cache, unless some sort of locking
is added (and waiting for a lock may be slower than simply running the
query without using the cache).

If there is a local nameserver, then it seems unlikely that an on-disk
cache is worthwhile, since the local server should be doing its own caching
and so the difference is loading (the entire cache) from disk compared to
doing a single query.  In memory caching is still likely to be beneficial
compared to querying the local nameserver, even when only a single message
is being processed per system process (since a single message may have
multiple links to the same hostname).

Therefore, this version of the module does not store the cache on disk, but
does cache in memory.  We use the dns package's cache object to handle the
caching.  We assume that this process is not excessively long-lived (i.e.
almost certainly less than an hour, typically only a few seconds), which
means that we can be more lax with caching as well (i.e. we can ignore the
TTL).

Other than these changes, we endeavour to keep the interface as similar as
possible, so that the module continues to be a drop-in replacement.
(We do lose the ability to print statistics at the end, since we do not
implement the cache ourselves).
"""

import time
import struct
import logging

import dns.resolver
import dns.exception
import dns.rdatatype
import dns.rdataclass

class cache(object):
    """Provide a simple-to-use interface to DNS lookups, which caches the
    results in memory."""
    def __init__(self, dnsServer=None, returnSinglePTR=True, dnsTimeout=10,
                 minTTL=0, cachefile=""):
        # We don't use the cachefile argument, but it may be provided.
        if cachefile:
            logging.getLogger('spambayes').warn(
                "Caching to file is not supported.")

        # As far as I (Matthew) can tell from the standards, it's legal to
        # have more than one PTR record for an address. That is, it's legal
        # to get more than one name back when you do a reverse lookup on an
        # IP address. I don't know of a use for that and I've never seen it
        # done. And I don't think that most people would expect it. So
        # forward ("A") lookups always return a list. Reverse ("PTR")
        # lookups return a single name unless this attribute is set to
        # False.
        self.returnSinglePTR = returnSinglePTR

        # Some servers always return a TTL of zero. In those cases, turning
        # this up a bit is probably reasonable.
        self.minTTL = minTTL

        self.queryObj = dns.resolver.Resolver()
        if dnsServer:
            self.queryObj.nameservers = [dnsServer]

        # How long to wait for the server (in seconds).
        # dnspython has a "timeout" value (for each nameserver) and a
        # "lifetime" value (for the complete query).  We're happy with the
        # 2 second default timeout, but want to limit the overall query.
        self.queryObj.lifetime = dnsTimeout

        # Use the package's caching system.
        self.queryObj.cache = dns.resolver.Cache()
        # Except that we also want to cache failures, because we are
        # generally short-lived, and sometimes errors are slow to generate.
        self.failures = {}

    def close(self):
        """Perform any cleanup necessary.

        Since we cannot print statistics on close, and since we do not need
        to write to disk, there is nothing to do here."""
        pass

    def lookup(self, question, qType="A", cType="IN", exact=False):
        """Do an actual lookup.  'question' should be the hostname or IP to
        query, and 'qType' should be the type of record to get (e.g. TXT,
        A, AAAA, PTR)."""
        rdtype = dns.rdatatype.from_text(qType)
        rdclass = dns.rdataclass.from_text(cType)
        try:
            return self.failures[question, rdtype, rdclass]
        except KeyError:
            pass
        reply = self.queryObj.cache.get((question, rdtype, rdclass))
        if not reply:
            try:
                reply = self.queryObj.query(question, rdtype, rdclass)
            except dns.resolver.NXDOMAIN:
                # This is actually a valid response, not an error condition.
                self.failures[question, rdtype, rdclass] = []
                return []
            except dns.exception.Timeout:
                # This may change next time this is run, so warn about that.
                logging.getLogger('spambayes').info(
                    "%s %s lookup timed out." % (question, qType))
                self.failures[question, rdtype, rdclass] = []
                return []
            except (dns.resolver.NoAnswer, dns.resolver.NoNameservers), e:
                if qType not in ("MX", "AAAA", "TXT"):
                    # These indicate a problem with the nameserver.
                    logging.getLogger('spambayes').debug(
                        "%s %s lookup failed: %s" % (question, qType, e))
                self.failures[question, rdtype, rdclass] = []
                return []
            except (ValueError, IndexError), e:
                # A bad DNS entry.
                logging.getLogger('spambayes').warn(
                    "%s %s lookup failed: %s" % (question, qType, e))
                self.failures[question, rdtype, rdclass] = []
                return []
            except struct.error, e:
                # A bad DNS entry.
                logging.getLogger('spambayes').warn(
                    "%s %s lookup failed: %s" % (question, qType, e))
                self.failures[question, rdtype, rdclass] = []
                return []
        self.queryObj.cache.put((question, rdtype, rdclass), reply)
        if exact:
            return [i.to_text() for sublist in
                    (answer.to_rdataset().items
                     for answer in reply.response.answer
                     if answer.rdtype == rdtype and
                     answer.rdclass == rdclass) for i in sublist]
        return [i.to_text()
                for i in reply.response.answer[0].to_rdataset().items]

def main():
    """Test / demonstrate the functionality, both using the cache and
    not."""
    from dns.reversename import from_address
    c = cache()
    for host in ("www.python.org", "www.timsbloggers.com",
                 "www.seeputofor.com", "www.completegarbage.tv",
                 "www.tradelinkllc.com", "www.ya.ru"):
        print "Checking", host
        now = time.time()
        ips = c.lookup(host, exact=True)
        print ips, time.time() - now
        now = time.time()
        ips = c.lookup(host, exact=True)
        print ips, time.time() - now
        if ips:
            ip = from_address(ips[0])
            now = time.time()
            name = c.lookup(ip, qType="PTR")
            print ip, name, time.time() - now
            now = time.time()
            name = c.lookup(ip, qType="PTR")
            print ip, name, time.time() - now
        else:
            print "unknown"
    c.close()

if __name__ == "__main__":
    main()
