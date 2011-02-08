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


/* Extended DNSSEC Validator's internal cache - shared with all window tabs */
org.os3sec.Extval.Cache = {

  flushTimer: null,
  flushInterval: 0,     // in seconds (0 is for cache disable)
  data: null,

  init: function() {

    // Create new array for caching
    this.data = new Array();

    // Get cache flush interval
    this.getFlushInterval();

    // Timer cache flushing is currently disabled
    /*
    // Create the timer for cache flushing
    if (dnssecExtension.debugOutput) {
      dump(dnssecExtension.debugPrefix + 'Initializing flush timer with interval: '
           + this.flushInterval + ' s\n');
    }

    this.flushTimer = Components.classes["@mozilla.org/timer;1"]
                                .createInstance(Components.interfaces.nsITimer);

    // Define cache flush timer callback
    this.flushTimer.initWithCallback(
      function() {
        dnssecExtCache.delExpiredRecords();
      },
      this.flushInterval * 1000,
      Components.interfaces.nsITimer.TYPE_REPEATING_SLACK); // repeat periodically
    */
  },

  getFlushInterval: function() {
    this.flushInterval = org.os3sec.Extval.Extension.prefs.getIntPref("cacheflushinterval");
  },

  addRecord: function(domainRecord) {

    // Get current time
    const cur_t = new Date().getTime();

    // Record expiration time
    domainRecord.exp_ttl = cur_t + domainRecord.ttl * 1000;   // expire4 is in seconds

    delete this.data[domainRecord.domain];
    this.data[domainRecord.domain] = domainRecord;
  },

  getRecord: function(n) {
    const c = this.data;

    if (typeof c[n] != 'undefined') {
      return c[n];
    }
    return new org.os3sec.Extval.DomainRecord();
  },

  printContent: function() {
    var i = 0;
    var n;
    const c = this.data;
    const cur_t = new Date().getTime();
    var ttl;

    org.os3sec.Extval.Extension.logMsg('Cache content:');

    for (n in c) {
      // compute TTL in seconds
      ttl = Math.round((c[n].exp_ttl - cur_t) / 1000);

      org.os3sec.Extval.Extension.logMsg('r' + i + ': \"' + n + '\": '
           + c[n].exp_ttl + ' (' + c[n].ttl + '); nxdomain:' + c[n].nxdomain + '; secure:' + c[n].secure +
            '; bogus:' + c[n].bogus + '; why_bogus:' + c[n].why_bogus +  '; sts:' + c[n].sts + '; sn:' + c[n].sn + '\n');
      i++;
    }
  },

  delExpiredRecords: function() {
    const c = this.data;

    // Get current time
    const cur_t = new Date().getTime();

    org.os3sec.Extval.Extension.logMsg('Flushing expired cache records...');

    for (n in c) {
      if (cur_t > c[n].exp_ttl ) {
        org.os3sec.Extval.Extension.logMsg('Deleting cache r: \"' + n + '\"');
        delete c[n];
      }
    }
  },

  delAllRecords: function() {

    org.os3sec.Extval.Extension.logMsg('Flushing all cache records...');

    delete this.data;
    this.data = new Array();
  },

  existsUnexpiredRecord: function(n) {
    const c = this.data;
    const cur_t = new Date().getTime();

    if (typeof c[n] != 'undefined') {
      return (cur_t <= c[n].exp_ttl);
    }
    return false;
  },

};
