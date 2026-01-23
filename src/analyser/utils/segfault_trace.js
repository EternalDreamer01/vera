// frida_segv_logger.js
// Defensive segfault logger: tries Process.setExceptionHandler then falls back to libc hooks.
// Prints basic context, backtrace (if available), and returns false (let OS handle crash).

(function(){
  'use strict';
  function now(){ return (new Date()).toISOString(); }
  function safeLog(){ try { console.log.apply(console, arguments); } catch(e){} }

  safeLog('[*] frida_segv_logger starting; checking APIs...');
  safeLog(' Process.setExceptionHandler ->', typeof Process.setExceptionHandler);
  safeLog(' Thread.backtrace ->', typeof (typeof Thread !== 'undefined' ? Thread.backtrace : undefined));
  safeLog(' DebugSymbol ->', typeof DebugSymbol);

  if (typeof Process.setExceptionHandler === 'function') {
    Process.setExceptionHandler(function(details) {
      try {
        safeLog('*** EXCEPTION (Frida) ***', now());
        safeLog(' type:', details.type, ' addr:', details.address, ' threadId:', details.threadId);
        try {
          if (details.context) {
            var regs = [];
            var i=0;
            for (var k in details.context) { if (i++>30) break; regs.push(k + '=' + details.context[k]); }
            safeLog(' regs:', regs.join(', '));
          }
        } catch(e){}
        // backtrace best-effort
        try {
          if (typeof Thread !== 'undefined' && typeof DebugSymbol !== 'undefined') {
            var bt = Thread.backtrace(details.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n');
            safeLog(' backtrace:\n' + bt);
          } else if (typeof Thread !== 'undefined') {
            var bt = Thread.backtrace(details.context, 16).map(function(a){ return a.toString(); }).join('\n');
            safeLog(' backtrace (fallback):\n' + bt);
          } else {
            safeLog(' backtrace not available');
          }
        } catch(e) { safeLog(' backtrace error', e); }
      } catch(e) { safeLog('handler error', e); }
      // Let default crash handling continue; do NOT attempt to resume.
      return false;
    });
    safeLog('[+] Process.setExceptionHandler installed');
    return;
  }

  safeLog('[!] Process.setExceptionHandler not available — installing libc fallback hooks');

  // Fallback: hook libc crash entry points
  function tryHook(name) {
    try {
      var addr = Module.findExportByName(null, name);
      if (!addr) return false;
      Interceptor.attach(addr, {
        onEnter: function(args) {
          try {
            safeLog('*** libc crash hook:', name, now());
            try {
              // if raise(sig) -> args[0] is sig
              if (args.length > 0) safeLog(' args[0]=', args[0]);
            } catch(e){}
            // try a small backtrace if possible
            try {
              if (typeof Thread !== 'undefined' && typeof DebugSymbol !== 'undefined') {
                var tb = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n');
                safeLog(' backtrace:\n' + tb);
              } else if (typeof Thread !== 'undefined') {
                var tb = Thread.backtrace(this.context, 16).map(function(a){return a.toString();}).join('\n');
                safeLog(' backtrace:\n' + tb);
              }
            } catch(e) { safeLog(' backtrace failed', e); }
          } catch(e){ }
        }
      });
      safeLog('[+] hooked', name, 'at', addr.toString());
      return true;
    } catch(e) { return false; }
  }

  tryHook('abort'); tryHook('raise'); tryHook('tgkill'); tryHook('pthread_kill');
})();
