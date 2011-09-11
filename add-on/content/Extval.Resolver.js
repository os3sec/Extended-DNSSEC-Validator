/* ***** BEGIN LICENSE BLOCK *****
 * This file is part of Extended DNSSEC Validator Add-on.
 *
 * Extended DNSSEC Validator Add-on is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * Extended DNSSEC Validator Add-on is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 *
 * You should have received a copy of the GNU General Public License along with
 * Extended DNSSEC Validator Add-on.  If not, see <http://www.gnu.org/licenses/>.
 * ***** END LICENSE BLOCK ***** */

/* Get security status through Libunbound call or from cache */
org.os3sec.Extval.Resolver = {
  
  // Determine the security of the domain and connection and, if necessary,
  // update the UI to reflect this. Intended to be called by onLocationChange.
  checkSecurity : function(uri) {

    // Set action state
    org.os3sec.Extval.UIHandler.setState(uri,org.os3sec.Extval.UIHandler.STATE_ACTION);

    // Remember last host name to eliminate duplicated queries
    // extvalExtension.oldAsciiHost = asciiHost;
    
    
    //Lookup ip used by browser
    var dnsService = Components.classes["@mozilla.org/network/dns-service;1"]
                     .getService(Components.interfaces.nsIDNSService);

    // Get browser's IP address(es) that uses to connect to the remote site.
    // Uses browser's internal resolver cache
    aRecord = dnsService.resolve(uri.asciiHost, 0);// Components.interfaces.nsIDNSService.RESOLVE_BYPASS_CACHE
	org.os3sec.Extval.Extension.logMsg('Browser dns lookup complete');
    this.onBrowserLookupComplete(uri, aRecord);
  },
  
  // Get validated data from cache or DNSResolver call
  getValidatedData: function(domain, resolvipv4, resolvipv6) {

    org.os3sec.Extval.Extension.logMsg('Getting IPv4/IPv6 record for "' + domain+ '" (' + resolvipv4 + '/' + resolvipv6 + ')...');
    
    var domainRecord;
    if (org.os3sec.Extval.Cache.existsUnexpiredRecord(domain, resolvipv4, resolvipv6)) {
      domainRecord = org.os3sec.Extval.Cache.getRecord(domain);
    } else {
      domainRecord = org.os3sec.Extval.DNSResolver.getDomainRecord(domain, resolvipv4, resolvipv6);
      
      if (org.os3sec.Extval.Cache.flushInterval) { // do not cache if 0
        org.os3sec.Extval.Cache.addRecord(domainRecord);
      }
    }
    return domainRecord;
  },
  
  // Called when browser async host lookup completes
  onBrowserLookupComplete: function(uri, aRecord) {

    //var domain = dnssecExtHandler._asciiHostName;
    var resolvipv4 = false; // No IPv4 resolving as default
    var resolvipv6 = false; // No IPv6 resolving as default
    var addr = null;
    
    while (aRecord && aRecord.hasMore()) {   // Address list is not empty
      addr = aRecord.getNextAddrAsString();
      // Check IP version
      if (addr.indexOf(":") != -1) {
        resolvipv6 = true;
      } else if (addr.indexOf(".") != -1) {
        resolvipv4 = true;
      }

      // No need to check more addresses
      if (resolvipv4 && resolvipv6) break;
    }

    org.os3sec.Extval.Extension.logMsg('Browser uses IPv4/IPv6 resolving: \"' + resolvipv4 + '/' + resolvipv6 + '\"');

    // Resolve IPv4 if no version is desired
    if (!resolvipv4 && !resolvipv6) resolvipv4 = true;

    // Get validated data from cache or by XPCOM call
    var domainRecord = this.getValidatedData(uri.asciiHost, resolvipv4, resolvipv6);
    
    // Temporary deleting of expired cache records until
    // cache flush timer will be working
    if (org.os3sec.Extval.Cache.flushInterval) {
      org.os3sec.Extval.Cache.delExpiredRecords();
    }
    
    org.os3sec.Extval.Cache.printContent();
    
    // Check if the IP used by the browser is valid
    var browserIPValid = this.checkBrowserIP(domainRecord.addresses,aRecord);
    
    // Stop if dnssec unsecured or bogus
    if(! this.setDNSSECState(uri,domainRecord,browserIPValid) ) {
    	return
    };
    
    //check if we're on a secure connection
    if(!uri.schemeIs("https")) {
        //check if https is available anyway
        //we have tlsa records, https should be available
        if(domainRecord.tlsa.length > 0) {
          org.os3sec.Extval.UIHandler.enableSwitchHttps(uri,true)
        }
    }
    else { //connection is https
      org.os3sec.Extval.CertTools.checkCertificate(uri, domainRecord);
    }
  },
  
  // Check browser's IP address(es)
  checkBrowserIP: function(validaddresses, aRecord) {
    var addr;
    var valid = true; // Browser's IP addresses are presumed as valid
    if (aRecord) {
      aRecord.rewind();
      while (aRecord.hasMore()) {   // Address list has another item
        addr = aRecord.getNextAddrAsString();
        // Check if each browser's address is present in DNSSEC address resolved list
        if (validaddresses.indexOf(addr) == -1) valid = false;

        org.os3sec.Extval.Extension.logMsg('Checking browser IP: ' + addr + '; address is valid: ' + valid + '');

        // No need to check more addresses
        if (!valid) return valid;
      }
    }
    return valid;
  },
  
  //Update the ui with appropriate dnssec state
  //Returns false on DNSSEC unsecured
  setDNSSECState: function(uri,domainRecord, browserIPValid) {
      //domain is not secured
      if(!domainRecord.secure && !domainRecord.bogus) {
        // check nxdomain
        if(domainRecord.nxdomain) {
          org.os3sec.Extval.UIHandler.setState(uri,org.os3sec.Extval.UIHandler.STATE_NXDOMAIN_UNSECURED);
          return false;
        } else {
          org.os3sec.Extval.UIHandler.setState(uri,org.os3sec.Extval.UIHandler.STATE_DOMAIN_UNSECURED);
          return false;
        }
      }
      //invalid dnssec signature
      else if(!domainRecord.secure && domainRecord.bogus) {
        org.os3sec.Extval.UIHandler.setState(uri,org.os3sec.Extval.UIHandler.STATE_DOMAIN_BOGUS);
        return false;
      }
      //secure denial of existence
      else if(domainRecord.nxdomain) {
        org.os3sec.Extval.UIHandler.setState(uri,org.os3sec.Extval.UIHandler.STATE_SECURE_NXDOMAIN);
      }
      //address is spoofed
      else if(!browserIPValid) {
        org.os3sec.Extval.UIHandler.setState(uri,org.os3sec.Extval.UIHandler.STATE_SECURE_ADDRESS_SPOOFED);
      //domain is secure, transport unsecure
      } else {
        org.os3sec.Extval.UIHandler.setState(uri,org.os3sec.Extval.UIHandler.STATE_SECURE_TRANSPORT_INSECURE);
      }
      
      return true;
  }
};
