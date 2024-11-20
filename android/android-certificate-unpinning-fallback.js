/**************************************************************************************************
 *
 * Once we've set up the configuration and certificate, and then disabled all the pinning
 * techniques we're aware of, we add one last touch: a fallback hook, designed to spot and handle
 * unknown unknowns.
 *
 * This can also be useful for heavily obfuscated apps, where 3rd party libraries are obfuscated
 * sufficiently that our hooks no longer recognize the methods we care about.
 *
 * To handle this, we watch for methods that throw known built-in TLS errors (these are *very*
 * widely used, and always recognizable as they're defined natively), and then subsequently patch
 * them for all future calls. Whenever a method throws this, we attempt to recognize it from
 * signatures alone, and automatically hook it.
 *
 * These are very much a fallback! They might not work! They almost certainly won't work on the
 * first request, so applications will see at least one failure. Even when they fail though, they
 * will at least log the method that's failing, so this works well as a starting point for manual
 * reverse engineering. If this does fail and cause problems, you may want to skip this script
 * and use only the known-good patches provided elsewhere.
 *
 * Source available at https://github.com/httptoolkit/frida-interception-and-unpinning/
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: Tim Perry <tim@httptoolkit.com>
 *
 *************************************************************************************************/
Java.perform(function () {
    try {
        const Thread = Java.use('java.lang.Thread');
        const Arrays = Java.use('java.util.Arrays');
        const SSLPeerUnverifiedException = Java.use('javax.net.ssl.SSLPeerUnverifiedException');
        const CertificateException = Java.use('java.security.cert.CertificateException');
        const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");

        const BASE_METHOD_ARGUMENTS = [
            '[Ljava.security.cert.X509Certificate;',
            'java.lang.String'
        ];
        const EXTENDED_METHOD_ARGUMENTS = [
            '[Ljava.security.cert.X509Certificate;',
            'java.lang.String',
            'java.lang.String'
        ];

        // Utility to fetch fields or methods via reflection
        const getFridaValues = (cls, values) =>
            values.map((value) => [value.getName(), cls[value.getName()]]);

        const getFields = (cls) => getFridaValues(cls, cls.class.getDeclaredFields());
        const getMethods = (cls) => getFridaValues(cls, cls.class.getDeclaredMethods());

        const matchOkHttpChain = (cls, expectedReturnTypeName) => {
            const methods = getMethods(cls).filter(([_, method]) =>
                method.returnType.className === expectedReturnTypeName &&
                method.argumentTypes.length === 1
            );

            if (methods.length !== 1) return;
            const [proceedMethodName, proceedMethod] = methods[0];
            const argumentTypeName = proceedMethod.argumentTypes[0].className;

            const fields = getFields(cls).filter(([_, field]) =>
                field.fieldReturnType?.className === argumentTypeName
            );

            if (fields.length !== 1) return;
            const [requestFieldName] = fields[0];

            return { proceedMethodName, requestFieldName };
        };

        const buildUnhandledErrorPatcher = (errorClassName, originalConstructor) => {
            return function (errorArg) {
                try {
                    console.log('\n !!! --- Unexpected TLS failure --- !!!');
                    const errorMessage = errorArg?.toString() ?? '';

                    const stackTrace = Thread.currentThread().getStackTrace();
                    const exceptionStackIndex = stackTrace.findIndex(stack =>
                        stack.getClassName() === errorClassName
                    );
                    const callingFunctionStack = stackTrace[exceptionStackIndex + 1];
                    const className = callingFunctionStack.getClassName();
                    const methodName = callingFunctionStack.getMethodName();

                    console.log(`      ${errorClassName.split('.').pop()}: ${errorMessage}`);
                    console.log(`      Thrown by ${className}->${methodName}`);

                    const callingClass = Java.use(className);
                    const callingMethod = callingClass[methodName];

                    callingMethod.overloads.forEach((failingMethod) => {
                        if (failingMethod.implementation) {
                            console.warn('      Already patched - but still failing!');
                            return;
                        }

                        if (errorMessage.startsWith("Certificate pinning failure!") &&
                            failingMethod.argumentTypes.length === 2 &&
                            failingMethod.argumentTypes[0].className === 'java.lang.String') {
                            failingMethod.implementation = () => {
                                if (DEBUG_MODE) console.log(` => Fallback OkHttp patch`);
                            };
                            console.log(`      [+] ${className}->${methodName} (fallback OkHttp patch)`);

                        } else if (errorMessage === 'Certificate transparency failed' &&
                            failingMethod.argumentTypes.length === 1) {
                            const chainClass = Java.use(failingMethod.argumentTypes[0].className);
                            const responseClassName = failingMethod.returnType.className;
                            const okHttpChain = matchOkHttpChain(chainClass, responseClassName);

                            if (okHttpChain) {
                                failingMethod.implementation = (chain) => {
                                    if (DEBUG_MODE) console.log(` => Fallback Appmattus+OkHttp patch`);
                                    const proceed = chain[okHttpChain.proceedMethodName].bind(chain);
                                    const request = chain[okHttpChain.requestFieldName].value;
                                    return proceed(request);
                                };
                                console.log(`      [+] ${className}->${methodName} (Fallback Appmattus+OkHttp patch)`);
                            }
                        } else if (methodName === 'checkServerTrusted' &&
                            X509TrustManager.class.isAssignableFrom(callingClass.class)) {
                            const argsMatchBase = failingMethod.argumentTypes.map(t => t.className).every((t, i) =>
                                BASE_METHOD_ARGUMENTS[i] === t);
                            const argsMatchExtended = failingMethod.argumentTypes.map(t => t.className).every((t, i) =>
                                EXTENDED_METHOD_ARGUMENTS[i] === t);

                            if (argsMatchBase && failingMethod.returnType.className === 'void') {
                                failingMethod.implementation = (certs, authType) => {
                                    if (DEBUG_MODE) console.log(` => Fallback X509TrustManager base patch`);
                                    const defaultTrustManager = getCustomX509TrustManager(); // Defined in unpinning script
                                    defaultTrustManager.checkServerTrusted(certs, authType);
                                };
                                console.log(`      [+] ${className}->${methodName} (Fallback X509TrustManager base patch)`);

                            } else if (argsMatchExtended && failingMethod.returnType.className === 'java.util.List') {
                                failingMethod.implementation = function (certs, authType, _hostname) {
                                    if (DEBUG_MODE) console.log(` => Fallback X509TrustManager ext patch`);
                                    try {
                                        const defaultTrustManager = getCustomX509TrustManager(); // Defined in unpinning script
                                        defaultTrustManager.checkServerTrusted(certs, authType);
                                    } catch (e) {
                                        console.error('Default TM threw:', e);
                                    }
                                    return Arrays.asList(certs);
                                };
                                console.log(`      [+] ${className}->${methodName} (Fallback X509TrustManager ext patch)`);
                            } else {
                                console.warn(`      [ ] Skipping unrecognized checkServerTrusted signature in class ${className}`);
                            }
                        } else {
                            console.error('      [ ] Unrecognized TLS error - manual patching needed');
                        }
                    });
                } catch (e) {
                    console.error('      [ ] Failed to auto-patch failure:', e);
                }

                return originalConstructor.call(this, ...arguments);
            };
        };

        // Install patches for known error types
        [
            SSLPeerUnverifiedException,
            CertificateException
        ].forEach((ErrorClass) => {
            ErrorClass.$init.overloads.forEach((overload) => {
                overload.implementation = buildUnhandledErrorPatcher(ErrorClass.$className, overload);
            });
        });

        console.log('== Unpinning fallback auto-patcher installed ==');
    } catch (err) {
        console.error(' !!! --- Unpinning fallback auto-patcher installation failed --- !!!', err);
    }
});
