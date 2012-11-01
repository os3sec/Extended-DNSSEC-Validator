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

org.os3sec.Extval.DomainRecord = function() {
    this.domain    = null;
    this.addresses = new Array();
    this.nxdomain  = null;
    this.secure    = null;
    this.bogus     = null;
    this.why_bogus = "";
    this.ttl       = 60;
    this.exp_ttl   = null;
    this.tlsa      = new Array();
  
    // we set Nxdomain when all lookups return nxdomain=true. Not good?
    this.setNxdomain = function(nxdomain) {
	if (this.nxdomain == null) {
	    this.nxdomain = nxdomain;
	} else {
	    this.nxdomain = (this.nxdomain && nxdomain);
	}
    };

    // Every record lookup must be secure to set the secure-flag. Good.
    this.setSecure = function(secure) {
	if (this.secure == null) {
	    this.secure = secure;
	} else {
	    this.secure = (this.secure && secure);
	}
    };
  
    // Any bogus lookup means the whole is bogus. Good.
    this.setBogus = function(bogus) {
	if(this.bogus == null) {
	    this.bogus = bogus;
	} else {
	    this.bogus = (this.bogus || bogus);
	}
    };
  
    // Capture all bogus-reasons
    this.setWhy_bogus = function(why_bogus) {
	this.why_bogus += why_bogus + " ";
    }
}


/* Do a validated DNS lookup using Libunbound */
org.os3sec.Extval.DNSResolver = {
    RRTYPE_A:     1,
    RRTYPE_AAAA: 28,
    RRTYPE_TLSA: 52,
  
    //Returns a domain record containing addresses, and txt records
    getDomainRecord: function(domain, resolvipv4, resolvipv6) {
	var domainRecord = this._doValidatedDomainLookup(domain, resolvipv4, resolvipv6);
	var dr2 = this._doValidatedTLSALookup(domain);
    
	// set domainrecord with 
	domainRecord.tlsa =       dr2.tlsa;
	domainRecord.setSecure(   dr2.secure);
	domainRecord.setBogus(    dr2.tlsa.bogus);
	domainRecord.setWhy_bogus(dr2.why_bogus);
	
	return domainRecord;
    },
  
    _doValidatedDomainLookup: function(domain, resolvipv4, resolvipv6) {
	org.os3sec.Extval.Extension.logMsg("Starting validated domain lookup using libunbound");
    
	var result = new org.os3sec.Extval.DomainRecord();
	result.domain = domain;
    
	//do v6 and/or v6 resolving and add results
	if(resolvipv4) {
	    var res = this._executeLibunbound(domain, this.RRTYPE_A);
	    result.addresses = result.addresses.concat(res.rdata);
	    result.setNxdomain( res.nxdomain != 0);
	    result.setSecure(   res.secure != 0);
	    result.setBogus(    res.bogus != 0);
	    result.setWhy_bogus(res.why_bogus);
	}
	if(resolvipv6) {
	    var res = this._executeLibunbound(domain, this.RRTYPE_AAAA);
	    result.addresses = result.addresses.concat(res.rdata);
	    result.setNxdomain( res.nxdomain != 0);
	    result.setSecure(   res.secure != 0);
	    result.setBogus(    res.bogus != 0);
	    result.setWhy_bogus(res.why_bogus);
	}
	
	return result;
    },
  
    parseTLSARecord: function(tlsaStr) {
	/*
         * Usage field
	 * Value        Short description                       
	 * -------------------------------------------------------------
	 * 0            CA Constraint
	 * 1            Service certificate constraint
         * 2            Trust anchor assertion
         * 3            Domain issued certicate
         * 4-254        Unassigned
	 *
	 * Reference:   https://tools.ietf.org/id/draft-ietf-dane-protocol-23
	 * and:         https://tools.ietf.org/html/rfc6394
         */
	var usage = parseInt(tlsaStr.substring(0,2));
		
        /*
         * Selector field
         * 0 -- Full certificate
         * 1 -- SubjectPublicKeyInfo
         */
	var selector = parseInt(tlsaStr.substring(2,4));

	/*
         * Matching type field
	 * Value        Short description       Ref.
	 * -----------------------------------------------------
	 * 0            Full cert            [This]
         * 1            SHA-256              NIST FIPS 180-2
         * 2            SHA-512              NIST FIPS 180-2
         * 3-254        Unassigned
         */
	var matchingType = parseInt(tlsaStr.substring(4,6));

	// This contains the certificate hash
	var certAssociation = tlsaStr.substring(6);

	return {usage:           usage,
		selector:        selector,
		matchingType:    matchingType,
		certAssociation: certAssociation.toUpperCase()};
    },

    _doValidatedTLSALookup: function(domain) {
	org.os3sec.Extval.Extension.logMsg("Starting validated cert lookup (TLSA) using libunbound");
    
	var domainRecord = new org.os3sec.Extval.DomainRecord();
	domainRecord.domain = domain;
    
	var res = this._executeLibunbound("_443._tcp."+domain, this.RRTYPE_TLSA);

	for(var i=0 in res.rdata) {
	    var tlsa = this.parseTLSARecord(res.rdata[i]);
	    domainRecord.tlsa.push(tlsa);

	    org.os3sec.Extval.Extension.logMsg("Found TLSA-Record: usage: " + tlsa.usage + 
					       ", selector: " + tlsa.selector + 
					       ", matchingType: " + tlsa.matchingType + 
					       ", associated: " + tlsa.certAssociation);
	}
	domainRecord.setNxdomain( res.nxdomain  != 0);
	domainRecord.setSecure(   res.secure    != 0);
	domainRecord.setBogus(    res.bogus     != 0);
	domainRecord.setWhy_bogus(res.why_bogus);
    
	return domainRecord;
    },

  _executeLibunbound : function(domain, rrtype) {
    org.os3sec.Extval.Extension.logMsg("execute libunbound for " + domain + ", rrtype: " + rrtype); 
    var result = new org.os3sec.Extval.Libunbound.ub_result_ptr();
    
    var retval = org.os3sec.Extval.Libunbound.ub_resolve(org.os3sec.Extval.Libunbound.ctx, domain,
      rrtype, 
      1, // CLASS IN (internet)
      result.address());
    
    var rdata = this.parseRdata(result.contents.len, result.contents.data, rrtype);
    
    return {rdata: rdata,
	    nxdomain:  result.contents.nxdomain.toString(),
	    secure:    result.contents.secure.toString(),
	    bogus:     result.contents.bogus.toString(),
	    why_bogus: result.contents.why_bogus.isNull() ? "" : result.contents.why_bogus.readString()
	   };
  },
  
  //parse rdata array from result set
  parseRdata : function(len,data,rrtype) {
    //len contains length of each item in data.
    //Iterate untill length = 0, which is the last item.
    //FIXME: find a nicer way for totalItems, currently limited with hardcoded max=10
    var lengthArray = ctypes.cast(len, ctypes.int.array(10).ptr);
    var totalLines = 0;
    var lengths = new Array();
    for(var i=0; i<10; i++) {
      //stop at 0 zero length
      if(lengthArray.contents[i].toString() == 0) {
        break;
      }
      //raise total items
      totalLines++;
      lengths.push(parseInt(lengthArray.contents[i].toString()));
    }
    
    var results = new Array();
    switch (rrtype) {
      case this.RRTYPE_A:
        //cast to 4 uint8 per rdata line
        var rdata = ctypes.cast(data, ctypes.uint8_t.array(4*totalLines).ptr.ptr);
        for (var i=0; i<4*totalLines; i+=4) {
          //concatenate and add to results 
          var ip = rdata.contents.contents[i].toString()
                    +"."+rdata.contents.contents[i+1].toString()
                    +"."+rdata.contents.contents[i+2].toString()
                    +"."+rdata.contents.contents[i+3].toString();
          results.push(ip);
        }
        break;
        
      case this.RRTYPE_AAAA:
        //cast to 16 uint8 per rdata line
        var rdata = ctypes.cast(data, ctypes.uint8_t.array(16*totalLines).ptr.ptr);
        for (var i=0; i<16*totalLines; i+=16) {
          //iterate over 16 uint8 and convert to char code
          var tmp = new String();
          for(var j=0; j<16; j++) {
            //inet_ntop('\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1')
            //octal representation of characters:
            //parseInt(rdata.contents.contents[i+j].toString(),10).toString(8)
            tmp += String.fromCharCode(rdata.contents.contents[i+j].toString());
          }
          //add ASCII representation to results
          results.push(this.inet6_ntop(tmp));
        }
        break;
      
      case this.RRTYPE_TLSA:
        var rdata = ctypes.cast(data, ctypes.char.ptr.array(totalLines).ptr);
        //iterate all lines
        for(var i=0; i<totalLines;i++) {
          //convert line to array of characters
          //parsing the complete string fails due to ending null character
	  org.os3sec.Extval.Extension.logMsg("Length: "+lengths[i]);
          var tmp = new String();
          var line = ctypes.cast(rdata.contents[i], ctypes.uint8_t.array(lengths[i]).ptr);
          var hex;
          //skip the first strange character
          for(var j=0; j<lengths[i];j++) {
            hex = org.os3sec.Extval.CertTools.charcodeToHexString(line.contents[j]);
			//hex = line.contents[j].toString(16);
			//if(hex < 16) { hex = "0" + hex; } // DONT LOOK AT ME

			tmp += hex;
          }
          results.push(tmp);
        }        
        break;
    }
    
    org.os3sec.Extval.Extension.logMsg("RData parsed: "+results);
    
    return results;
  },
  
  //Converts a packed inet6 address to a human readable IP address string
  //Source: http://phpjs.org/functions/inet_ntop:882
  //original by: Theriault
  inet6_ntop : function(a) {
    var i = 0, m = '', c = [];
    a += '';
    if (a.length === 16) { // IPv6 length
        for (i = 0; i < 16; i++) {
            c.push(((a.charCodeAt(i++) << 8) + a.charCodeAt(i)).toString(16));
        }
        return c.join(':').replace(/((^|:)0(?=:|$))+:?/g, function (t) {
            m = (t.length > m.length) ? t : m;
            return t;
        }).replace(m || ' ', '::');
    } else { // Invalid length
        return false;
    }
  }
}
