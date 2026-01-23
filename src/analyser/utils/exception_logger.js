// frida_exception_logger.js
// Attach with: frida -U -p <PID> -l frida_exception_logger.js

'use strict';

var backtracer = Module.findExportByName('libc.so', 'backtrace'); // optional
Process.setExceptionHandler(function(details) {
  try {
    console.log('*** EXCEPTION ***');
    console.log('type:', details.type);               // e.g. 'signal'
    console.log('address:', details.address);         // faulting address
    console.log('threadId:', details.threadId);
    // print context registers if present
    if (details.context) {
      var regs = details.context;
      // architecture-dependent — Frida exposes named registers on context object
      console.log('context:', JSON.stringify(Object.keys(regs)));
      // A simple register dump:
      for (var r in regs) {
        try { console.log(r + ": " + regs[r]); } catch(e) {}
      }
    }
    // Backtrace (best-effort)
    try {
      var bt = Thread.backtrace(details.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress).join('\n');
      console.log('Backtrace:\n' + bt);
    } catch (e) {
      console.log('Backtrace failed:', e);
    }
  } catch (e) {
    console.log('exception handler error:', e);
  }
  // return false -> let process crash normally (produce tombstone)
  // return true  -> indicate handled; process will continue (risky)
  return false;
});
console.log('Exception handler installed.');