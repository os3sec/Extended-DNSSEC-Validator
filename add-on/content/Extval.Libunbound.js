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

Components.utils.import("resource://gre/modules/ctypes.jsm");
Components.utils.import("resource://gre/modules/AddonManager.jsm"); 

org.os3sec.Extval.Libunbound = {
  lib: null,  //libunbound library reference
  
  init: function() {
  	AddonManager.getAddonByID("extended-validator@os3sec.org", function(addon) {
  		
  		var abi = Components.classes["@mozilla.org/xre/app-info;1"]
          		.getService(Components.interfaces.nsIXULRuntime)
		        .XPCOMABI;
		var os = Components.classes["@mozilla.org/xre/app-info;1"]
                        .getService(Components.interfaces.nsIXULRuntime)
                        .OS;
        
        org.os3sec.Extval.Extension.logMsg("OS: " + os + " ABI: " +abi);

		try {
			//navigator.platform
			if(os.match("Darwin")) {
				var libunboundFile = "libunbound.dylib";
			} else if(os.match("WINNT")) {
				var libunboundFile = "libunbound-2.dll";
			} else if(os.match("Linux")) {
				var libunboundFile = "libunbound.so.2";
			} else {
				//We should support every OS that runs libunbound and firefox. Mail us (or roll your own and submit a patch :-) )
				org.os3sec.Extval.Extension.logMsg("Unsupported OS");

				//XXX Gracefully exit and display something to the user.
			}

			Libunbound._init(libunboundFile);
		}
		catch(e) {
			// Failed loading from OS libs. Fall back to libraries distributed with plugin.
			if(os.match("Darwin")) {
				var libunboundFile = addon.getResourceURI("components/libunbound.dylib")
					.QueryInterface(Components.interfaces.nsIFileURL).file.path;
			} else if(os.match("Linux") && abi.match("x86_64")) {
				var libunboundFile = addon.getResourceURI("components/libunbound64.so.2.7.0")
					.QueryInterface(Components.interfaces.nsIFileURL).file.path;
				//Libunbound._init(libunboundFile.path);
			} else if(os.match("Linux") && abi.match("x86")) {
				var libunboundFile = addon.getResourceURI("components/libunbound.so.2.7.0")
						.QueryInterface(Components.interfaces.nsIFileURL).file.path;
			} else if(os.match("WINNT")) {
				var env = Components.classes["@mozilla.org/process/environment;1"].
					getService(Components.interfaces.nsIEnvironment);
				env.set("PATH", env.get("PATH") +";" + addon.getResourceURI("components/win/")
						.QueryInterface(Components.interfaces.nsIFileURL).file.path);
				var libunboundFile = addon.getResourceURI("components/win/libunbound-2.dll")
						.QueryInterface(Components.interfaces.nsIFileURL).file.path;
			}
			org.os3sec.Extval.Libunbound._init(libunboundFile);
		}
	});
  },
  
  _init: function(libunboundFile) {
    org.os3sec.Extval.Extension.logMsg("Loading libunbound from: "+libunboundFile);
  	
    this.lib = ctypes.open(libunboundFile);
    //declare structs
    this.ub_ctx = ctypes.StructType("ub_ctx");      //Opaque structure internally, no need to know contents here
    var ub_result = ctypes.StructType("ub_result", 
        [{  qname         : ctypes.char.ptr     },  /* text string, original question */
        {   qtype         : ctypes.int          },  /* type code asked for */
        {   qclass        : ctypes.int          },  /* class code asked for */
        {   data          : ctypes.char.ptr.ptr },  /* array of rdata items, NULL terminated*/
        {   len           : ctypes.int.ptr      },  /* array with lengths of rdata items */
        {   canonname     : ctypes.char.ptr     },  /* canonical name of result */
        {   rcode         : ctypes.int          },  /* additional error code in case of no data */
        {   answer_packet : ctypes.voidptr_t    },  /* full network format answer packet */
        {   answer_len    : ctypes.int          },  /* length of packet in octets */
        {   havedata      : ctypes.int          },  /* true if there is data */
        {   nxdomain      : ctypes.int          },  /* true if nodata because name does not exist */
        {   secure        : ctypes.int          },  /* true if result is secure */
        {   bogus         : ctypes.int          },  /* true if a security failure happened */
        {   why_bogus     : ctypes.char.ptr     }]) /* string with error if bogus */
    
    this.ub_result_ptr = ctypes.PointerType(ub_result);
    
    //declare functions
    this.ub_ctx_create = this.lib.declare("ub_ctx_create",
        ctypes.default_abi,
        this.ub_ctx.ptr);
        
    this.ub_ctx_resolvconf = this.lib.declare("ub_ctx_resolvconf",
        ctypes.default_abi,
        ctypes.int,
        this.ub_ctx.ptr,        //ctx
        ctypes.char.ptr);       //fname
    
    this.ub_ctx_set_fwd = this.lib.declare("ub_ctx_set_fwd",
        ctypes.default_abi,
        ctypes.int,
        this.ub_ctx.ptr,        //ctx
        ctypes.char.ptr);       //forward address
    
    this.ub_ctx_add_ta = this.lib.declare("ub_ctx_add_ta",
        ctypes.default_abi,
        ctypes.int,
        this.ub_ctx.ptr,        //ctx
        ctypes.char.ptr);       //trusted anchor
    
    this.ub_resolve = this.lib.declare("ub_resolve",
        ctypes.default_abi,
        ctypes.int,
        this.ub_ctx.ptr,        //ctx
        ctypes.char.ptr,        //name
        ctypes.int,             //rrtype
        ctypes.int,             //rrclass
        this.ub_result_ptr.ptr);//result

    this.ub_ctx_set_option = this.lib.declare("ub_ctx_set_option",
        ctypes.default_abi,
        ctypes.int,
        this.ub_ctx.ptr,        //ctx
        ctypes.char.ptr,        //optname
        ctypes.char.ptr);       //optvaluea
  
    //create context
    this.ctx = this.ub_ctx_create();
    this.ub_ctx_resolvconf(this.ctx,null);
    
    //enable forwarder if desired
    var fwd = org.os3sec.Extval.Extension.prefs.getCharPref("dnsforwarder");
    if(fwd != "") {
       org.os3sec.Extval.Extension.logMsg("Using dns forwarder:"+fwd);
       this.ub_ctx_set_fwd(this.ctx,fwd);	
    }
    
    //load the rootanchor from preferences
    var rootanchor = org.os3sec.Extval.Extension.prefs.getCharPref("rootanchor");
    //define default rootanchor if it's empty
    if(rootanchor == "") {
      rootanchor = ". 86400 IN DNSKEY 257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF FVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoX bfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaD X6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpz W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relS Qageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulq QxA+Uk1ihz0=";
    }
    // load the dlvanchor from preferences
    var dlvanchor = org.os3sec.Extval.Extension.prefs.getCharPref("dlvanchor");
    if(dlvanchor == "") {
      dlvanchor = "dlv.isc.org. 86400 IN DNSKEY 257 3 5 BEAAAAPHMu/5onzrEE7z1egmhg/WPO0+juoZrW3euWEn4MxDCE1+lLy2 brhQv5rN32RKtMzX6Mj70jdzeND4XknW58dnJNPCxn8+jAGl2FZLK8t+ 1uq4W+nnA3qO2+DL+k6BD4mewMLbIYFwe0PG73Te9fZ2kJb56dhgMde5 ymX4BI/oQ+cAK50/xvJv00Frf8kw6ucMTwFlgPe+jnGxPPEmHAte/URk Y62ZfkLoBAADLHQ9IrS2tryAe7mbBZVcOwIeU/Rw/mRx/vwwMCTgNboM QKtUdvNXDrYJDSHZws3xiRXF1Rf+al9UmZfSav/4NWLKjHzpT59k/VSt TDN0YUuWrBNh";
    }

    //add trusted anchor to libunbound context
    this.ub_ctx_add_ta(this.ctx, rootanchor);
    // add DLV trust anchor to libunbound context
    this.ub_ctx_set_option(this.ctx, "dlv-anchor:", dlvanchor);
  },
  
  shutdown: function() {
    this.lib.close();
  }
}
