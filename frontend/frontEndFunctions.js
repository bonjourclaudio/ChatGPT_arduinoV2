const looper = createStemLooper({
  files: [
    "/assets/tracks/01.wav",
    "/assets/tracks/02.wav",
    "/assets/tracks/03.wav",
    "/assets/tracks/04.wav",
    "/assets/tracks/05.wav",
    "/assets/tracks/06.wav",
    "/assets/tracks/07.wav",
    "/assets/tracks/08.wav",
  ],
});

looper.load(() => {
  console.log("--- Stem looper loaded ---");
});

window.frontendFunctions = {
  start_party: function (command) {
    console.log("Starting party mode");
    function createGlitter() {
      const glitter = document.createElement("div");
      glitter.style.position = "absolute";
      glitter.style.width = "10px";
      glitter.style.height = "10px";
      glitter.style.background = `radial-gradient(circle, ${getRandomColor()}, rgba(255, 255, 255, 0))`;
      glitter.style.borderRadius = "50%";
      glitter.style.left = Math.random() * 100 + "vw";
      glitter.style.top = "0";
      glitter.style.opacity = "1";
      glitter.style.transition = `transform ${
        Math.random() * 3 + 2
      }s linear, opacity ${Math.random() * 3 + 2}s linear`;
      document.body.appendChild(glitter);

      requestAnimationFrame(() => {
        glitter.style.transform = "translateY(100vh)";
        glitter.style.opacity = "0";
      });

      setTimeout(() => {
        glitter.remove();
      }, 5000);
    }
    function getRandomColor() {
      const colors = [
        "red",
        "blue",
        "green",
        "yellow",
        "purple",
        "pink",
        "orange",
      ];
      return colors[Math.floor(Math.random() * colors.length)];
    }

    let partyEffect = setInterval(createGlitter, 10);
    // stop after 10 seconds
    setTimeout(() => {
      clearInterval(partyEffect);
    }, 10000);
  },
  get_value: function (command) {
    console.log("Starting party mode");
    return Math.random() * 100;
  },
  set_value: function (command) {
    console.log("Setting value to:", command);
  },
  start_default_music: function (command) {
    looper.startTrack(0);
    looper.startTrack(1);
    looper.startTrack(2);
    looper.startTrack(3);
  },
  play_track: function (command) {
    // command is track number 1-8 -> index 0-7
    // could also be 45 -> play tracks 4 and 5

    let digits = command.toString().split("");
    digits.forEach((d) => {
      let trackIndex = parseInt(d) - 1;
      if (trackIndex >= 0 && trackIndex < 8) {
        looper.startTrack(trackIndex);
      }
    });
  },
  stop_track: function (command) {
    looper.stopTrack(1);
  },
};

// Debug logging to visible console on page
function debugLog(message) {
  console.log(message);
  const debugOutput = document.getElementById("debugOutput");
  if (debugOutput) {
    const timestamp = new Date().toLocaleTimeString();
    debugOutput.innerHTML += `<div>[${timestamp}] ${message}</div>`;
    debugOutput.scrollTop = debugOutput.scrollHeight;
  }
}

// Fetch and display latest image from scratch folder

async function updateLatestImage() {
  try {
    const res = await fetch("http://localhost:3000/api/latest-image");

    if (!res.ok) {
      console.error(`❌ HTTP ${res.status}: ${res.statusText}`);
      document.getElementById("latestImage").style.display = "none";
      return;
    }

    const data = await res.json();
    console.log("✓ API response:", data);

    if (data.image) {
      console.log("📸 Displaying:", data.image);
      const img = document.getElementById("latestImage");
      img.src = "http://localhost:3000" + data.image + "?" + Date.now();
      img.style.display = "block";
    } else {
      console.log("⚠️  No image available yet");
      document.getElementById("latestImage").style.display = "none";
    }
  } catch (err) {
    console.error("❌ Error fetching image:", err);
    document.getElementById("latestImage").style.display = "none";
  }
}

// Update every 1 second
//setInterval(updateLatestImage, 2000);

// Initial fetch
updateLatestImage();

// #######################
// ---- Stem looper  ----
function createStemLooper(opts) {
  const cfg = Object.assign(
    {
      files: null,
      minutesTarget: 10,
      xfadeMs: 60,
      fadeInSec: 0.02,
      fadeOutSec: 0.03,
      masterGain: 1,
      autoMix: true,
      latencyHint: "playback",
    },
    opts || {}
  );

  if (!cfg.files || cfg.files.length !== 8) {
    throw new Error("Expected `files` to be an array of 8 track URLs.");
  }

  // ---- Web Audio graph ----
  const ctx = new (window.AudioContext || window.webkitAudioContext)({
    latencyHint: cfg.latencyHint,
  });

  const master = ctx.createGain();
  master.gain.value = cfg.masterGain;
  master.connect(ctx.destination);

  const trackGains = Array.from({ length: 8 }, () => {
    const g = ctx.createGain();
    g.gain.value = 0;
    g.connect(master);
    return g;
  });

  // ---- State ----
  var megaBuffers = []; // AudioBuffer[8]
  var sources = Array(8).fill(null); // active AudioBufferSourceNode | null
  var active = new Set(); // playing track indexes
  var t0 = null; // common reference time
  var destroyed = false;

  // ---- Helpers (no async/await) ----
  function equalPowerInOut(t) {
    // t in [0..1]
    return {
      inW: Math.sin((t * Math.PI) / 2),
      outW: Math.cos((t * Math.PI) / 2),
    };
  }

  function loadArrayBuffer(url, onOK, onErr) {
    // fetch -> arrayBuffer (Promise chain, no async/await)
    fetch(url)
      .then((r) => {
        if (!r.ok) throw new Error("Failed to load " + url);
        return r.arrayBuffer();
      })
      .then(onOK)
      .catch(onErr);
  }

  function decodeToAudioBuffer(arrBuf, onOK, onErr) {
    // Use callback flavor to avoid await
    ctx.decodeAudioData(
      arrBuf.slice(0),
      function (buf) {
        onOK(buf);
      },
      function (e) {
        onErr(e || new Error("decodeAudioData failed"));
      }
    );
  }

  function resampleToDeviceSR(buf, onOK, onErr) {
    var sr = ctx.sampleRate;
    if (buf.sampleRate === sr) {
      onOK(buf);
      return;
    }
    // Offline render at device SR; use oncomplete instead of Promise
    var frames = Math.max(1, Math.round(buf.duration * sr));
    var off = new OfflineAudioContext(buf.numberOfChannels, frames, sr);
    var src = off.createBufferSource();
    src.buffer = buf;
    src.connect(off.destination);
    src.start(0);
    off.oncomplete = function (e) {
      onOK(e.renderedBuffer);
    };
    off.startRendering().catch(onErr);
  }

  function buildMegaBuffer(srcBuf, minutesTarget, xfadeMs) {
    var sr = ctx.sampleRate;
    var ch = srcBuf.numberOfChannels;
    var clipFrames = srcBuf.length;
    var xfadeFrames = Math.max(0, Math.floor((xfadeMs / 1000) * sr));
    var totalFramesTarget = Math.max(
      clipFrames,
      Math.round(minutesTarget * 60 * sr)
    );

    var stride = Math.max(1, clipFrames - xfadeFrames);
    var repeats = Math.max(
      1,
      Math.ceil((totalFramesTarget - clipFrames) / stride) + 1
    );
    var finalFrames = clipFrames + (repeats - 1) * stride;

    var out = ctx.createBuffer(ch, finalFrames, sr);

    // First copy
    for (var c = 0; c < ch; c++) {
      out.getChannelData(c).set(srcBuf.getChannelData(c), 0);
    }

    // Repeats with equal-power crossfade
    var writePos = clipFrames;
    for (var r = 1; r < repeats; r++) {
      var overlapStart = writePos - xfadeFrames;

      for (var c2 = 0; c2 < ch; c2++) {
        var dst = out.getChannelData(c2);
        var s = srcBuf.getChannelData(c2);

        // overlap region
        for (var i = 0; i < xfadeFrames; i++) {
          var t = (i + 1) / (xfadeFrames || 1);
          var w = equalPowerInOut(t);
          var a = dst[overlapStart + i];
          var b = s[i];
          dst[overlapStart + i] = a * w.outW + b * w.inW;
        }
        // remainder after overlap
        dst.set(s.subarray(xfadeFrames), overlapStart + xfadeFrames);
      }

      writePos = overlapStart + clipFrames;
    }

    return out;
  }

  function now() {
    return ctx.currentTime;
  }

  function computePerTrackTarget() {
    if (!cfg.autoMix) return 1.0;
    var n = Math.max(1, active.size || 1);
    return 1 / Math.sqrt(n);
    // simple power summation model; good enough for stems
  }

  function retargetActiveGains(at) {
    var t = at || now();
    var target = computePerTrackTarget();
    var ramp = 0.08;
    active.forEach(function (i) {
      var g = trackGains[i].gain;
      g.cancelScheduledValues(t);
      g.setValueAtTime(g.value, t);
      g.linearRampToValueAtTime(target, t + ramp);
    });
  }

  function currentPhaseOffset(i, at) {
    // Align to shared reference so toggling tracks keeps them in time
    if (!t0) return 0;
    var dur = megaBuffers[i].duration;
    var elapsed = Math.max(0, (at || now()) - t0);
    return dur > 0 ? elapsed % dur : 0;
  }

  function startSource(i, when, offsetSec) {
    var src = ctx.createBufferSource();
    src.buffer = megaBuffers[i];
    // The mega-buffer is long; no need to loop unless you want it truly endless.
    // Uncomment for endless looping:
    // src.loop = true;
    src.connect(trackGains[i]);
    src.start(when, Math.max(0, offsetSec || 0));
    sources[i] = src;
  }

  // ---- Public methods ----
  function load(onReady, onError) {
    if (destroyed) return onError && onError(new Error("Instance destroyed"));
    ctx
      .resume()
      .then(function () {
        // sequentially load+decode+resample each file (simple control flow)
        var decoded = [];
        var idx = 0;

        function next() {
          if (idx >= 8) {
            // build mega-buffers
            megaBuffers = [];
            for (var k = 0; k < 8; k++) {
              megaBuffers.push(
                buildMegaBuffer(decoded[k], cfg.minutesTarget, cfg.xfadeMs)
              );
            }
            t0 = now() + 0.5; // first-reference time
            if (onReady) onReady();
            return;
          }

          var url = cfg.files[idx];
          loadArrayBuffer(
            url,
            function (arr) {
              decodeToAudioBuffer(
                arr,
                function (buf) {
                  resampleToDeviceSR(
                    buf,
                    function (bufSR) {
                      decoded[idx] = bufSR;
                      idx++;
                      next();
                    },
                    function (e3) {
                      if (onError) onError(e3);
                    }
                  );
                },
                function (e2) {
                  if (onError) onError(e2);
                }
              );
            },
            function (e1) {
              if (onError) onError(e1);
            }
          );
        }

        next();
      })
      .catch(function (e) {
        if (onError) onError(e);
      });
  }

  function startTrack(i, opts) {
    if (i < 0 || i >= 8) throw new Error("Track index must be 0..7");
    if (!megaBuffers[i]) throw new Error("Call load() before starting tracks.");
    if (sources[i]) return; // already playing

    var o = opts || {};
    var fadeIn = Math.max(0, o.fadeInSec != null ? o.fadeInSec : cfg.fadeInSec);
    var at = Math.max(now() + 0.01, o.at != null ? o.at : now() + 0.01);

    // ensure common reference
    if (!t0) t0 = now() + 0.5;

    // set gain 0, ramp to target
    var g = trackGains[i].gain;
    var target = cfg.autoMix ? computePerTrackTarget() : 1.0;
    g.cancelScheduledValues(at);
    g.setValueAtTime(0, Math.max(now(), at - fadeIn));
    g.linearRampToValueAtTime(target, at + fadeIn);

    // phase-consistent offset
    var offset = currentPhaseOffset(i, at);
    startSource(i, at, offset);

    active.add(i);
    if (cfg.autoMix) retargetActiveGains(at);
  }

  function stopTrack(i, opts) {
    if (i < 0 || i >= 8) throw new Error("Track index must be 0..7");
    var src = sources[i];
    if (!src) return;

    var o = opts || {};
    var fadeOut = Math.max(
      0,
      o.fadeOutSec != null ? o.fadeOutSec : cfg.fadeOutSec
    );
    var at = Math.max(now() + 0.01, o.at != null ? o.at : now() + 0.01);

    var g = trackGains[i].gain;
    g.cancelScheduledValues(at);
    g.setValueAtTime(g.value, at);
    g.linearRampToValueAtTime(0, at + fadeOut);

    try {
      src.stop(at + fadeOut + 0.01);
    } catch (e) {}
    sources[i] = null;
    active.delete(i);

    if (cfg.autoMix && active.size) retargetActiveGains(at);
  }

  function stopAll(opts) {
    for (var i = 0; i < 8; i++) stopTrack(i, opts);
  }

  function setMasterGain(v) {
    var t = now();
    var val = Math.max(0, Math.min(1, v));
    master.gain.cancelScheduledValues(t);
    master.gain.setValueAtTime(master.gain.value, t);
    master.gain.linearRampToValueAtTime(val, t + 0.05);
  }

  function destroy() {
    if (destroyed) return;
    destroyed = true;
    try {
      stopAll({ fadeOutSec: 0.01 });
    } catch (e) {}
    master.disconnect();
    try {
      ctx.close();
    } catch (e) {}
  }

  return {
    load,
    startTrack,
    stopTrack,
    stopAll,
    setMasterGain,
    destroy,
    // (optional) introspection
    getContext: function () {
      return ctx;
    },
    get activeTracks() {
      return new Set(active);
    },
    get buffersReady() {
      return megaBuffers.length === 8;
    },
  };
}
