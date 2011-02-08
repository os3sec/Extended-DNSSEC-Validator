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

//Define our namespace
if(!org) var org={};
if(!org.os3sec) org.os3sec={};
if(!org.os3sec.Extval) org.os3sec.Extval={};

window.addEventListener("load", function() { org.os3sec.Extval.Extension.init(); }, false);
window.addEventListener("unload", function() { org.os3sec.Extval.Extension.uninit(); }, false);

/*
 * Main extension object
 */
org.os3sec.Extval.Extension = {
  extvalExtID: "extended-validator@os3sec.org",
  debugOutput: false,
  debugPrefix: "extval: ",
  prefBranch : "extensions.extval.",
  prefs: null,

  init: function() {
    //initilize our preferences
    this.prefs = Components.classes["@mozilla.org/preferences-service;1"]
                 .getService(Components.interfaces.nsIPrefService)
                 .getBranch(this.prefBranch);
    this.prefs.QueryInterface(Components.interfaces.nsIPrefBranch2);
    this.prefs.addObserver("", this, false);

    
    // Read initial preferences
    this.getDebugOutputFlag(); // Enable debugging information on stdout if desired
    
    //initialize the UI and libunbound context
    org.os3sec.Extval.UIHandler.init();
    org.os3sec.Extval.Cache.init();
    org.os3sec.Extval.Libunbound.init();
    
    // Set error mode (no icon)
    org.os3sec.Extval.UIHandler.setState(null,org.os3sec.Extval.UIHandler.STATE_ERROR);

    // Add a progress listener to the urlbar
    //gBrowser.addProgressListener(extvalUrlBarListener, Components.interfaces.nsIWebProgress.NOTIFY_LOCATION);
    var flags = 0;
    flags |= Components.interfaces.nsIWebProgress.NOTIFY_ALL;
    flags |= Components.interfaces.nsIWebProgress.NOTIFY_STATE_ALL;
    gBrowser.addProgressListener(org.os3sec.Extval.UrlBarListener, flags);
  },
  
  /*
   * If debugout is enabled, log the message to console
   */
  logMsg: function(msg) {
  	if(this.debugOutput) {
  		dump(this.debugPrefix + msg + "\n");
  	}
  },

  getDebugOutputFlag: function() {
    this.debugOutput = this.prefs.getBoolPref("debugoutput");
  },

  uninit: function() {
    gBrowser.removeProgressListener(org.os3sec.Extval.UrlBarListener);
    this.prefs.removeObserver("",this);
    org.os3sec.Extval.Libunbound.shutdown();
  },

  /*
   * Called when events occur
   */
  observe: function(aSubject, aTopic, aData) {
    if (aTopic != "nsPref:changed") return;

    switch (aData) {
    case "debugoutput":
      this.getDebugOutputFlag();
      break;
    case "dnsserver":
      org.os3sec.Extval.Cache.delAllRecords();
      break;
    case "cacheflushinterval":
      org.os3sec.Extval.Cache.getFlushInterval();
      if (!extvalCache.flushInterval) extvalCache.delAllRecords();
      break;
    }
  },

  processNewURL: function(aLocationURI) {
    var scheme = null;
    var asciiHost = null;
    var utf8Host = null;
    
    //prevent NS_ERRORS from StringBundle
    try {
      scheme = aLocationURI.scheme;             // Get URI scheme
      asciiHost = aLocationURI.asciiHost;       // Get punycoded hostname
      utf8Host = aLocationURI.host;             // Get UTF-8 encoded hostname
    } catch(ex) {}

    this.logMsg('Scheme: "' + scheme + '"; ' + 'ASCII domain name: "' + asciiHost + '"');

    if (scheme == 'chrome' ||                   // Eliminate chrome scheme
        asciiHost == null ||
        asciiHost == '' ||                      // Empty string
        asciiHost.indexOf("\\") != -1 ||        // Eliminate addr containing '\'
        asciiHost.indexOf(":") != -1 ||         // Eliminate IPv6 addr notation
        asciiHost.search(/[A-Za-z]/) == -1) {   // Eliminate IPv4 addr notation

      if (this.debugOutput) dump(' ...invalid');

      // Set error mode (no icon)
      org.os3sec.Extval.UIHandler.setState(org.os3sec.Extval.UIHandler.STATE_ERROR);
      
      return;
    }

    this.logMsg(' ...valid');

    // Check DNS security
    org.os3sec.Extval.Resolver.checkSecurity(aLocationURI);
  }
};

org.os3sec.Extval.UrlBarListener = {
  
  //window location changed, also happens on changing tabs
  onLocationChange: function(aWebProgress, aRequest, aLocationURI) {
    //domainRecord is already cached by now,
    //only ui needs to be updated from here
    org.os3sec.Extval.Extension.processNewURL(aLocationURI);
  },

  onSecurityChange: function(aWebProgress, aRequest, aState) {
      org.os3sec.Extval.Extension.processNewURL(window.gBrowser.currentURI);
  },
  
  onStateChange: function(aWebProgress, aRequest, aStateFlags, aStatus) {
  },
  
  onProgressChange: function(aWebProgress, aRequest,
                             aCurSelfProgress, aMaxSelfProgress,
                             aCurTotalProgress, aMaxTotalProgress) {},
  
  onStatusChange: function(aWebProgress, aRequest, aStatus, aMessage)
  {}
};
