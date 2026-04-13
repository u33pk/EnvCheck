(function() {
    'use strict';

    function sendData(key, value) {
        if (window.FingerprintBridge) {
            window.FingerprintBridge.onFingerprintData(key, String(value));
        }
    }

    // 1. User Agent
    sendData('userAgent', navigator.userAgent);

    // 2. WebView 版本相关
    var webviewVersion = 'unknown';
    var ua = navigator.userAgent;
    var chromeMatch = ua.match(/Chrome\/(\d+\.\d+\.\d+\.\d+)/);
    var safariMatch = ua.match(/Safari\/(\d+\.\d+)/);
    var webviewMatch = ua.match(/Version\/(\d+\.\d+)/);
    if (chromeMatch) webviewVersion = 'Chrome: ' + chromeMatch[1];
    else if (webviewMatch) webviewVersion = 'WebView: ' + webviewMatch[1];
    else if (safariMatch) webviewVersion = 'Safari: ' + safariMatch[1];
    
    sendData('webviewVersion', webviewVersion);
    sendData('appVersion', navigator.appVersion);
    sendData('platform', navigator.platform);

    // 3. Canvas 2D 指纹
    try {
        var canvas = document.getElementById('canvas2d');
        var ctx = canvas.getContext('2d');
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillStyle = '#f60';
        ctx.fillRect(0, 0, 200, 50);
        ctx.fillStyle = '#069';
        ctx.fillText('WebView Fingerprint 中文测试', 2, 15);
        ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
        ctx.fillText('!@#$%^&*()', 2, 35);
        
        var canvasData = canvas.toDataURL();
        // 计算简单的 hash
        var hash = 0;
        for (var i = 0; i < canvasData.length; i++) {
            var char = canvasData.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        sendData('canvas2dHash', '0x' + Math.abs(hash).toString(16));
        sendData('canvas2dLength', canvasData.length);
    } catch (e) {
        sendData('canvas2dHash', 'error: ' + e.message);
        sendData('canvas2dLength', 0);
    }

    // 4. WebGL 指纹
    try {
        var glCanvas = document.getElementById('webgl');
        var gl = glCanvas.getContext('webgl') || glCanvas.getContext('experimental-webgl');
        
        if (gl) {
            // WebGL Vendor 和 Renderer
            var debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            if (debugInfo) {
                var vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
                var renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
                sendData('webglVendor', vendor || 'unknown');
                sendData('webglRenderer', renderer || 'unknown');
            } else {
                sendData('webglVendor', 'restricted');
                sendData('webglRenderer', 'restricted');
            }
            
            // WebGL 参数指纹
            var params = [
                gl.VENDOR,
                gl.RENDERER,
                gl.VERSION,
                gl.SHADING_LANGUAGE_VERSION,
                gl.MAX_TEXTURE_SIZE,
                gl.MAX_VIEWPORT_DIMS,
                gl.MAX_VERTEX_ATTRIBS,
                gl.MAX_VERTEX_UNIFORM_VECTORS,
                gl.MAX_FRAGMENT_UNIFORM_VECTORS
            ];
            var paramValues = params.map(function(p) {
                try {
                    var val = gl.getParameter(p);
                    return val ? val.toString() : 'null';
                } catch(e) {
                    return 'error';
                }
            });
            var webglHash = paramValues.join('|');
            var webglHashNum = 0;
            for (var j = 0; j < webglHash.length; j++) {
                var c = webglHash.charCodeAt(j);
                webglHashNum = ((webglHashNum << 5) - webglHashNum) + c;
                webglHashNum = webglHashNum & webglHashNum;
            }
            sendData('webglHash', '0x' + Math.abs(webglHashNum).toString(16));
        } else {
            sendData('webglVendor', 'not supported');
            sendData('webglRenderer', 'not supported');
            sendData('webglHash', '0');
        }
    } catch (e) {
        sendData('webglVendor', 'error: ' + e.message);
        sendData('webglRenderer', 'error');
        sendData('webglHash', '0');
    }

    // 5. 字体检测
    try {
        var fonts = ['Arial', 'Times New Roman', 'Courier New', 'Georgia', 'Verdana', 
                     'Helvetica', 'Tahoma', 'Trebuchet MS', 'Palatino', 'Garamond',
                     'Bookman', 'Comic Sans MS', 'Impact', '宋体', '微软雅黑', 
                     '黑体', '楷体', '仿宋', '新宋体', 'PingFang SC'];
        var detectedFonts = [];
        var testString = 'mmmmmmmmmmlli';
        var testSize = '72px';
        var body = document.body;
        
        var span = document.createElement('span');
        span.style.fontSize = testSize;
        span.style.position = 'absolute';
        span.style.left = '-9999px';
        span.innerHTML = testString;
        body.appendChild(span);
        
        var baseWidth = span.offsetWidth;
        var baseHeight = span.offsetHeight;
        
        for (var k = 0; k < fonts.length; k++) {
            span.style.fontFamily = fonts[k] + ', monospace';
            if (span.offsetWidth !== baseWidth || span.offsetHeight !== baseHeight) {
                detectedFonts.push(fonts[k]);
            }
        }
        
        body.removeChild(span);
        sendData('detectedFonts', detectedFonts.join(', '));
        sendData('fontCount', detectedFonts.length);
    } catch (e) {
        sendData('detectedFonts', 'error: ' + e.message);
        sendData('fontCount', 0);
    }

    // 6. AudioContext 指纹
    try {
        var AudioContext = window.AudioContext || window.webkitAudioContext;
        if (AudioContext) {
            var audioCtx = new AudioContext();
            var oscillator = audioCtx.createOscillator();
            var analyser = audioCtx.createAnalyser();
            var gainNode = audioCtx.createGain();
            
            oscillator.type = 'triangle';
            oscillator.frequency.value = 10000;
            
            gainNode.gain.value = 0;
            
            oscillator.connect(analyser);
            analyser.connect(gainNode);
            gainNode.connect(audioCtx.destination);
            
            oscillator.start();
            
            var audioData = new Uint8Array(analyser.frequencyBinCount);
            analyser.getByteFrequencyData(audioData);
            
            var audioSum = 0;
            for (var m = 0; m < audioData.length; m++) {
                audioSum += audioData[m];
            }
            var audioHash = '0x' + (audioSum % 0xFFFFFF).toString(16);
            
            oscillator.stop();
            audioCtx.close();
            
            sendData('audioHash', audioHash);
            sendData('audioSampleRate', audioCtx.sampleRate);
            sendData('audioBaseLatency', audioCtx.baseLatency || 'unknown');
        } else {
            sendData('audioHash', 'not supported');
            sendData('audioSampleRate', 0);
            sendData('audioBaseLatency', 'n/a');
        }
    } catch (e) {
        sendData('audioHash', 'error: ' + e.message);
        sendData('audioSampleRate', 0);
    }

    // 7. 屏幕和视口信息
    sendData('screenWidth', screen.width);
    sendData('screenHeight', screen.height);
    sendData('screenColorDepth', screen.colorDepth);
    sendData('screenPixelRatio', window.devicePixelRatio);
    sendData('viewportWidth', window.innerWidth);
    sendData('viewportHeight', window.innerHeight);

    // 8. 时区和语言
    sendData('timezone', Intl.DateTimeFormat().resolvedOptions().timeZone);
    sendData('timezoneOffset', new Date().getTimezoneOffset());
    sendData('language', navigator.language);
    sendData('languages', navigator.languages ? navigator.languages.join(', ') : navigator.language);

    // 9. 硬件并发数
    sendData('hardwareConcurrency', navigator.hardwareConcurrency || 'unknown');

    // 10. 设备内存
    sendData('deviceMemory', navigator.deviceMemory || 'unknown');

    // 11. 触摸支持
    sendData('maxTouchPoints', navigator.maxTouchPoints || 0);
    sendData('touchEvent', 'ontouchstart' in window ? 'yes' : 'no');

    // 12. 其他特征
    sendData('cookieEnabled', navigator.cookieEnabled);
    sendData('doNotTrack', navigator.doNotTrack || 'unknown');
    sendData('pdfViewerEnabled', navigator.pdfViewerEnabled ? 'yes' : 'no');

    // 通知完成
    sendData('fingerprintComplete', 'true');
})();
