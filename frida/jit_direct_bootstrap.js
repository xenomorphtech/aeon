'use strict';

(function () {
    if (typeof rpc === 'undefined' || !rpc) {
        throw new Error('Frida rpc global is unavailable');
    }
    rpc.exports = rpc.exports || {};

    function describeJavaObject(System, obj) {
        if (obj === null || obj === undefined) {
            return null;
        }
        try {
            var cls = obj.getClass ? obj.getClass() : null;
            var className = cls ? cls.getName().toString() : null;
            var ident = System ? System.identityHashCode(obj) : null;
            var out = {
                kind: 'object',
                className: className,
                identityHashCode: ident,
            };
            try {
                if (className === 'java.lang.String') {
                    out.kind = 'string';
                    out.value = obj.toString();
                } else if (className === 'java.lang.Integer' ||
                           className === 'java.lang.Long' ||
                           className === 'java.lang.Short' ||
                           className === 'java.lang.Byte' ||
                           className === 'java.lang.Boolean' ||
                           className === 'java.lang.Float' ||
                           className === 'java.lang.Double') {
                    out.kind = 'boxed';
                    out.value = obj.toString();
                } else if (className && className.indexOf('[') === 0 && obj.length !== undefined) {
                    out.kind = 'array';
                    out.length = obj.length;
                }
            } catch (_) {}
            return out;
        } catch (e) {
            return {
                kind: 'error',
                error: String(e),
            };
        }
    }

    rpc.exports.probeNmss = function () {
        var result = {
            classLoaded: false,
            instExists: false,
            className: null,
            instClassName: null,
            instIdentityHashCode: null,
            declaredMethods: [],
            declaredFieldCount: 0,
            staticFields: [],
            instanceFields: [],
            error: null,
        };

        Java.performNow(function () {
            try {
                var NmssSa = Java.use('nmss.app.NmssSa');
                var System = Java.use('java.lang.System');
                var Modifier = Java.use('java.lang.reflect.Modifier');
                var cls = NmssSa.class;
                var fields = cls.getDeclaredFields();
                var methods = cls.getDeclaredMethods();
                var inst = null;

                result.classLoaded = true;
                result.className = cls.getName().toString();
                result.declaredFieldCount = fields.length;
                for (var m = 0; m < methods.length && m < 40; m++) {
                    try {
                        result.declaredMethods.push(methods[m].toString());
                    } catch (_) {}
                }

                try {
                    inst = NmssSa.getInstObj();
                } catch (e) {
                    result.getInstObjError = String(e);
                }

                if (inst) {
                    result.instExists = true;
                    try {
                        result.instClassName = inst.getClass().getName().toString();
                    } catch (_) {}
                    try {
                        result.instIdentityHashCode = System.identityHashCode(inst);
                    } catch (_) {}
                }

                for (var i = 0; i < fields.length && i < 64; i++) {
                    var f = fields[i];
                    try { f.setAccessible(true); } catch (_) {}
                    var name = null;
                    var typeName = null;
                    var isStatic = false;
                    try { name = f.getName().toString(); } catch (_) {}
                    try { typeName = f.getType().getName().toString(); } catch (_) {}
                    try { isStatic = Modifier.isStatic(f.getModifiers()); } catch (_) {}
                    var entry = {
                        name: name,
                        type: typeName,
                        static: isStatic,
                    };
                    try {
                        var value = f.get(isStatic ? null : inst);
                        entry.value = describeJavaObject(System, value);
                    } catch (e) {
                        entry.error = String(e);
                    }
                    if (isStatic) {
                        result.staticFields.push(entry);
                    } else {
                        result.instanceFields.push(entry);
                    }
                }
            } catch (e) {
                result.error = String(e);
            }
        });

        return result;
    };

    rpc.exports.probeNmssSummary = function () {
        var full = rpc.exports.probeNmss();

        function findField(fields, name) {
            for (var i = 0; i < fields.length; i++) {
                if (fields[i].name === name) return fields[i];
            }
            return null;
        }

        function scalarValue(entry) {
            if (!entry) return null;
            if (entry.value && typeof entry.value === 'object' && 'value' in entry.value) {
                return entry.value.value;
            }
            return entry.value || null;
        }

        function classValue(entry) {
            if (!entry) return null;
            if (entry.value && typeof entry.value === 'object' && 'className' in entry.value) {
                return entry.value.className;
            }
            return null;
        }

        var instFields = full.instanceFields || [];
        var staticFields = full.staticFields || [];
        return {
            classLoaded: full.classLoaded,
            instExists: full.instExists,
            instIdentityHashCode: full.instIdentityHashCode,
            m_bAppExit: scalarValue(findField(instFields, 'm_bAppExit')),
            m_bIsRPExists: scalarValue(findField(instFields, 'm_bIsRPExists')),
            m_nCode: scalarValue(findField(instFields, 'm_nCode')),
            m_strMsg: scalarValue(findField(instFields, 'm_strMsg')),
            m_activityClass: classValue(findField(instFields, 'm_activity')),
            m_detectCallBackClass: classValue(findField(instFields, 'm_detectCallBack')),
            m_bShowMsg: scalarValue(findField(staticFields, 'm_bShowMsg')),
            m_adid: scalarValue(findField(staticFields, 'm_adid')),
            m_aid: scalarValue(findField(staticFields, 'm_aid')),
            error: full.error,
        };
    };

    rpc.exports.callCert = function (challenge) {
        var token = '';
        Java.performNow(function () {
            try {
                var NmssSa = Java.use('nmss.app.NmssSa');
                var inst = NmssSa.getInstObj();
                if (!inst) {
                    token = '';
                    return;
                }
                var result = inst.getCertValue(challenge);
                token = result ? result.toString() : '';
            } catch (e) {
                token = 'ERR:' + e;
            }
        });
        return token || '';
    };
})();
