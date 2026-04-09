// One-shot NMSS readiness probe.
//
// Usage:
//   adb -s localhost:5556 shell monkey -p com.netmarble.thered -c android.intent.category.LAUNCHER 1
//   sleep 6
//   frida -H 127.0.0.1:27042 -p $(adb -s localhost:5556 shell pidof com.netmarble.thered | tr -d '\r') -q -l aeon-ollvm/frida/nmss_prepare_once.js -e ''
//
// This follows the confirmed safe sequence on the main thread:
//   onResume() -> run(READY_CHALLENGE) -> getCertValue(READY_CHALLENGE)

'use strict';

var READY_CHALLENGE = '6BA4D60738580083';

function currentActivity() {
    var ActivityThread = Java.use('android.app.ActivityThread');
    var thread = ActivityThread.currentActivityThread();
    if (!thread) return null;
    try {
        var activities = thread.mActivities.value;
        var iter = activities.values().iterator();
        var fallback = null;
        while (iter.hasNext()) {
            var record = iter.next();
            var activity = record.activity.value;
            if (!activity) continue;
            if (fallback === null) fallback = activity;
            try {
                if (!record.paused.value) return activity;
            } catch (e) {
                return activity;
            }
        }
        return fallback;
    } catch (e) {
        try {
            return ActivityThread.currentApplication();
        } catch (inner) {
            return null;
        }
    }
}

Java.perform(function () {
    try {
        var activity = currentActivity();
        console.log('ACT=' + (activity ? activity.getClass().getName() : 'null'));

        var NmssSa = Java.use('nmss.app.NmssSa');
        var inst = NmssSa.getInstObj();
        console.log('INST=' + (inst !== null));
        if (!inst) {
            console.log('NO_INSTANCE');
            return;
        }

        var Handler = Java.use('android.os.Handler');
        var Looper = Java.use('android.os.Looper');
        var CountDownLatch = Java.use('java.util.concurrent.CountDownLatch');
        var TimeUnit = Java.use('java.util.concurrent.TimeUnit');
        var latch = CountDownLatch.$new(1);

        var RunnableClass = Java.registerClass({
            name: 'com.aeon.PrepareOnce' + Date.now(),
            implements: [Java.use('java.lang.Runnable')],
            methods: {
                run: function () {
                    try {
                        var sa = NmssSa.getInstObj();
                        console.log('SA=' + (sa !== null));

                        console.log('STEP=onResume');
                        try {
                            sa.onResume();
                            console.log('onResume:ok');
                        } catch (e) {
                            console.log('onResume:err:' + e);
                        }

                        console.log('STEP=run');
                        try {
                            var runResult = sa.run(READY_CHALLENGE);
                            console.log('run:ret:' + runResult);
                        } catch (e) {
                            console.log('run:err:' + e);
                        }

                        console.log('STEP=getCertValue');
                        try {
                            var cert = sa.getCertValue(READY_CHALLENGE);
                            console.log('CERT=' + (cert ? cert.toString() : ''));
                        } catch (e) {
                            console.log('cert:err:' + e);
                        }
                    } finally {
                        latch.countDown();
                    }
                }
            }
        });

        Handler.$new(Looper.getMainLooper()).post(RunnableClass.$new());
        var ok = latch.await(20, TimeUnit.SECONDS.value);
        console.log('LATCH=' + ok);
    } catch (e) {
        console.log('TOPERR=' + e + '\n' + e.stack);
    }
});
