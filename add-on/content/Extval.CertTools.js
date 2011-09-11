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

/*
 * Certificate functions
 */
org.os3sec.Extval.CertTools = {
  
  overrideService: Components.classes["@mozilla.org/security/certoverride;1"]
					.getService(Components.interfaces.nsICertOverrideService),
          
  state : {
      STATE_IS_BROKEN : 
	      Components.interfaces.nsIWebProgressListener.STATE_IS_BROKEN,
      STATE_IS_INSECURE :
	      Components.interfaces.nsIWebProgressListener.STATE_IS_INSECURE,
      STATE_IS_SECURE :
	      Components.interfaces.nsIWebProgressListener.STATE_IS_SECURE
  },

  
  //Checks if the certificate presented by the uri is valid
  //Based on Perspectives addon
  //Source: https://github.com/danwent/Perspectives
  checkCertificate: function(uri, domainRecord) {
    //won't work if we're not on https
    if(!uri.schemeIs("https")){ return };
    
    org.os3sec.Extval.Extension.logMsg('Connection is https, checking certificates...');
          
    var cert = this.getCertificate(window.gBrowser);
    if(!cert) {
      org.os3sec.Extval.Extension.logMsg('Unable to get a certificate');
      
      org.os3sec.Extval.UIHandler.setState(uri,org.os3sec.Extval.UIHandler.STATE_CERT_ERROR);
      
      return;
    }
    
    var state = window.gBrowser.securityUI.state;

    var is_override_cert = this.overrideService.isCertUsedForOverrides(cert, true, true);
    
    org.os3sec.Extval.Extension.logMsg('is_override_cert = ' + is_override_cert);

    // see if the browser has this cert installed prior to this browser session
    // seems like we can't tell the difference between an exception added by the user
    // manually and one we installed permemently during a previous browser run.
    var secureConnection = !(state & this.state.STATE_IS_INSECURE);
    var browser_trusted = secureConnection && !(is_override_cert);
    
    org.os3sec.Extval.Extension.logMsg('browser_trusted = ' + browser_trusted);
    
    var dns_trusted = this.is_trusted_by_dns(cert, domainRecord);
    
    org.os3sec.Extval.Extension.logMsg('dns_trusted = ' + dns_trusted);
    
    if(!dns_trusted && is_override_cert) {
      org.os3sec.Extval.Extension.logMsg('Should remove override, dnssec not trusted');
      //this.removeOverride
      org.os3sec.Extval.UIHandler.setState(uri,org.os3sec.Extval.UIHandler.STATE_CERT_INVALID_DNSSEC);
    }
    
    if(browser_trusted && !dns_trusted) {
      org.os3sec.Extval.UIHandler.setState(uri,org.os3sec.Extval.UIHandler.STATE_CERT_CA);
    }
    
    if(dns_trusted) {
      //if trusted but not on secure connection, override the trust
      if(! secureConnection) {
		if(this.do_override(window.gBrowser, cert)) {
		  org.os3sec.Extval.Extension.logMsg('Certificate trust is overrided');
		}
      }
      
      //set UI state
      if(browser_trusted) {
	    org.os3sec.Extval.UIHandler.setState(uri,org.os3sec.Extval.UIHandler.STATE_CERT_DNSSEC_CA);
      } else {
	    org.os3sec.Extval.UIHandler.setState(uri,org.os3sec.Extval.UIHandler.STATE_CERT_DNSSEC);
      }
      
      return;
    }
  },
  
  //checks if certificate can be validated using dnssec
  is_trusted_by_dns: function(cert, domainRecord) {
    //var sha1 = cert.sha1Fingerprint.replace(/:/g,'').toUpperCase();
    for(i=0;i<domainRecord.tlsa.length;i++) {
        if ( this.check_cert(cert,domainRecord.tlsa[i]) ) {
            return true;
        }
    }
    return false;
  },

  check_cert: function(cert, tlsa_record) {
    var ihash = Components.interfaces.nsICryptoHash;
    var hasher = Components.classes["@mozilla.org/security/hash;1"].createInstance(ihash);
    if (tlsa_record[2] == 1) {
        hasher.init(ihash.SHA256);
    }
    else if (tlsa_record[2] == 2) {
        hasher.init(ihash.SHA512);
    }
    else {
        //0 type (exact content) not supported yet
        return false
    }

    var len = {};
    var der = cert.getRawDER(len);
    hasher.update(der, len.value);
    var binHash = hasher.finish(false);
    // convert the binary hash data to a hex string.
    var s = [this.charcodeToHexString(binHash.charCodeAt(i)) for (i in binHash)].join("").toUpperCase();
    org.os3sec.Extval.Extension.logMsg("checking tlsa record: " + s + " / " + tlsa_record[3]);
    return s == tlsa_record[3];
  },

  charcodeToHexString: function(charcode) {
    return ("0" + charcode.toString(16)).slice(-2);
  },
  
  //gets valid or invalid certificate used by the browser
  getCertificate: function(browser) {
    var uri = browser.currentURI;
    var ui = browser.securityUI;
    var cert = this.get_valid_cert(ui);
    if(!cert){
      cert = this.get_invalid_cert(uri);
    }

    if(!cert) {
      return null;
    }
    return cert;
  },
  
  // gets current certificate, if it PASSED the browser check 
  get_valid_cert: function(ui) {
    try { 
      ui.QueryInterface(Components.interfaces.nsISSLStatusProvider); 
      if(!ui.SSLStatus) 
	      return null; 
      return ui.SSLStatus.serverCert; 
    }
    catch (e) {
      org.os3sec.Extval.Extension.logMsg('get_valid_cert: ' + e);
      return null;
    }
  },
  
  // gets current certificate, if it FAILED the security check
  get_invalid_cert: function(uri) {
    var gSSLStatus = this.get_invalid_cert_SSLStatus(uri);
		if(!gSSLStatus){
			return null;
		}
		return gSSLStatus.QueryInterface(Components.interfaces.nsISSLStatus)
				.serverCert;
  },
  
  get_invalid_cert_SSLStatus: function(uri) {
    var recentCertsSvc = 
		Components.classes["@mozilla.org/security/recentbadcerts;1"]
			.getService(Components.interfaces.nsIRecentBadCertsService);
		if (!recentCertsSvc)
			return null;

		var port = (uri.port == -1) ? 443 : uri.port;  

		var hostWithPort = uri.host + ":" + port;
		var gSSLStatus = recentCertsSvc.getRecentBadCert(hostWithPort);
		if (!gSSLStatus)
			return null;
		return gSSLStatus;
  },
  
  //Override the certificate as trusted
  do_override: function(browser, cert) { 
    var uri = browser.currentURI;
    
    org.os3sec.Extval.Extension.logMsg('Overriding certificate trust ');
    
    //Get SSL status (untrusted flags)
    var gSSLStatus = this.get_invalid_cert_SSLStatus(uri);
    if(gSSLStatus == null) { 
	    return false; 
    } 
    var flags = 0;
    if(gSSLStatus.isUntrusted)
	    flags |= this.overrideService.ERROR_UNTRUSTED;
    if(gSSLStatus.isDomainMismatch)
	    flags |= this.overrideService.ERROR_MISMATCH;
    if(gSSLStatus.isNotValidAtThisTime)
	    flags |= this.overrideService.ERROR_TIME;
    //override the certificate trust
    this.overrideService.clearValidityOverride(uri.asciiHost, uri.port);
    this.overrideService.rememberValidityOverride(uri.asciiHost, uri.port, cert, flags, true);

    setTimeout(function (){ browser.loadURIWithFlags(uri.spec, flags);}, 25);
  }
}
