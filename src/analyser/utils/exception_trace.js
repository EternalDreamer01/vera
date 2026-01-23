// trace_with_stack.js
// Hook exported functions matching PATTERN and print stack trace on enter.
// Usage: edit PATTERN below and run:
//   frida -U -p <PID> -l trace_with_stack.js
//
// CAUTION: hooking many functions is noisy and expensive. Start narrow.

'use strict';

////////////////////////////////////////////////////////////////////////////////
// CONFIG
////////////////////////////////////////////////////////////////////////////////
var PATTERN = /^(sqlite3_|xmlParse)/;        // change to the regex you want, e.g. /^open$/ or /./ for everything
var STACK_LIMIT = 30;             // max frames to print
var PRINT_ARGS = true;            // print first few args (best-effort)
var MAX_HOOKS = 1000;             // safety limit on number of functions to hook
var RATE_LIMIT_MS = 50;           // per-thread minimum ms between prints to avoid flood
////////////////////////////////////////////////////////////////////////////////

function now() { return (new Date()).toISOString(); }
function safeLog() { try { console.log.apply(console, arguments); } catch(e) {} }

safeLog("[*] trace_with_stack starting");
safeLog("[*] PATTERN:", PATTERN.toString(), "STACK_LIMIT:", STACK_LIMIT, "PRINT_ARGS:", PRINT_ARGS);

// check API availability
var hasEnumModules = (typeof Process.enumerateModulesSync === 'function');
var hasEnumExports = (typeof Module.enumerateExportsSync === 'function');
var hasFindExport = (typeof Module.findExportByName === 'function');
var hasThreadBacktrace = (typeof Thread !== 'undefined' && typeof Thread.backtrace === 'function');
var hasDebugSymbol = (typeof DebugSymbol !== 'undefined' && typeof DebugSymbol.fromAddress === 'function');
safeLog("[*] API availability: enumerateModulesSync=", !!hasEnumModules,
         " enumerateExportsSync=", !!hasEnumExports,
         " findExportByName=", !!hasFindExport,
         " Thread.backtrace=", !!hasThreadBacktrace,
         " DebugSymbol=", !!hasDebugSymbol);

// rate limiting per thread
var lastPrintByThread = {};

function recordRateLimit() {
  try {
    var tid = Process.getCurrentThreadId ? Process.getCurrentThreadId() : (this.threadId || 0);
    var nowMs = Date.now();
    var last = lastPrintByThread[tid] || 0;
    if (nowMs - last < RATE_LIMIT_MS) return false;
    lastPrintByThread[tid] = nowMs;
    return true;
  } catch (e) { return true; }
}

function tryBacktrace(context) {
  try {
    if (hasThreadBacktrace && hasDebugSymbol) {
      var bt = Thread.backtrace(context, Backtracer.ACCURATE).slice(0, STACK_LIMIT);
      return bt.map(function(addr){ try { return DebugSymbol.fromAddress(addr).toString(); } catch(e){ return addr.toString(); } });
    } else if (hasThreadBacktrace) {
      var bt = Thread.backtrace(context, STACK_LIMIT);
      return bt.map(function(addr){ return addr.toString(); });
    } else {
      return ["<no Thread.backtrace available in this runtime>"];
    }
  } catch (e) {
    try {
      // fallback small attempt
      if (typeof Thread !== 'undefined' && typeof Thread.backtrace === 'function') {
        var bt2 = Thread.backtrace(context, STACK_LIMIT);
        return bt2.map(function(a){ return a.toString(); });
      }
    } catch (ee){}
    return ["<backtrace failed: " + e + ">"];
  }
}

function printArgs(args) {
  try {
    var out = [];
    for (var i = 0; i < Math.min(4, args.length); i++) {
      try {
        var a = args[i];
        // try to print pointer value / string
        if (a && typeof a.readUtf8String === 'function') {
          out.push('arg' + i + '=' + a + ' (str=' + (Memory.readUtf8String(a) || "<no-str>") + ')');
        } else {
          // NativePointer or primitive
          out.push('arg' + i + '=' + a);
        }
      } catch (e) {
        out.push('arg' + i + '=<err>');
      }
    }
    return out.join(', ');
  } catch (e) {
    return '<args-print-failed>';
  }
}

function attachToExport(modName, exp) {
  try {
    var addr = exp.address || exp;
    Interceptor.attach(addr, {
      onEnter: function(args) {
        try {
          if (!recordRateLimit.call(this)) return;
          safeLog('---');
          safeLog(now(), 'ENTER', (exp.name || '<addr>'), 'module=' + (modName || '<unknown>'), 'addr=' + addr.toString());
          if (PRINT_ARGS) {
            try {
              safeLog(' ARGS:', printArgs(args));
            } catch(e){}
          }
          // print stack
          var bt = tryBacktrace(this.context);
          safeLog(' STACK:');
          for (var i = 0; i < bt.length; i++) safeLog('  ' + bt[i]);
        } catch(e) {
          safeLog('[error] onEnter handler', e);
        }
      }
    });
    return true;
  } catch (e) {
    // if attaching by name failed, try nothing
    return false;
  }
}

function installHooksForModuleExports(mod) {
  var hooked = 0;
  try {
    var exps = [];
    if (hasEnumExports) {
      try {
        exps = Module.enumerateExportsSync(mod.name);
      } catch(e) {
        // fallback: try findExport for common names? skip
        exps = [];
      }
    } else {
      // try to use Module.findExportByName with a few guesses (not ideal)
      exps = [];
    }
    for (var i = 0; i < exps.length; i++) {
      var e = exps[i];
      if (e.type !== 'function') continue;
      if (!e.name) continue;
      if (!PATTERN.test(e.name)) continue;
      if (hooked >= MAX_HOOKS) break;
      if (attachToExport(mod.name, { name: e.name, address: e.address })) {
        hooked++;
      }
    }
  } catch (e) {}
  return hooked;
}

// main: enumerate modules and hook exports that match PATTERN
(function main() {
  try {
    var mods = [];
    if (hasEnumModules) {
      try {
        mods = Process.enumerateModulesSync();
      } catch(e) { mods = []; }
    } else {
      // try a small set of likely modules
      var likely = ['libc.so','libm.so','libdl.so','libsqlite.so','libsqlite3.so'];
      mods = [];
      likely.forEach(function(n){ try { mods.push({name:n}); } catch(e){} });
    }

    var totalHooks = 0;
    for (var i = 0; i < mods.length; i++) {
      try {
        var m = mods[i];
        var count = installHooksForModuleExports(m);
        if (count > 0) safeLog("[*] hooked", count, "exports in module", m.name);
        totalHooks += count;
        if (totalHooks >= MAX_HOOKS) break;
      } catch(e){}
    }

    if (totalHooks === 0) {
      safeLog("[!] No exported functions matched PATTERN or exports enumeration unavailable.");
      safeLog("[!] Options:");
      safeLog("  - narrow PATTERN to a known exported symbol name (e.g. /^sqlite3_prepare_v2$/)");
      safeLog("  - set PATTERN to the exact function name or use module+offset hooking (see earlier scripts).");
      safeLog("  - use frida-trace -U -p <PID> -i \"<pattern>\" to let frida-trace attempt tracing.");
    } else {
      safeLog("[*] DONE. Installed total hooks:", totalHooks);
    }
  } catch (e) {
    safeLog("[!] main error:", e);
  }
})();
