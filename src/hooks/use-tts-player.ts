import { useSyncExternalStore } from "react";
import { toast } from "sonner";

type Status = "idle" | "loading" | "playing" | "paused";

type State = {
  status: Status;
  activeKey: string | null;
  activeText: string;
  duration: number;
  currentTime: number;
  level: number; // 0..1 audio reactive level
};

const listeners = new Set<() => void>();
let state: State = {
  status: "idle",
  activeKey: null,
  activeText: "",
  duration: 0,
  currentTime: 0,
  level: 0,
};
let audio: HTMLAudioElement | null = null;
let currentUrl: string | null = null;
let rafId: number | null = null;

let audioCtx: AudioContext | null = null;
let analyser: AnalyserNode | null = null;
let sourceNode: MediaElementAudioSourceNode | null = null;
let freqData: Uint8Array | null = null;

function setState(patch: Partial<State>) {
  state = { ...state, ...patch };
  listeners.forEach((l) => l());
}

function subscribe(cb: () => void) {
  listeners.add(cb);
  return () => {
    listeners.delete(cb);
  };
}

function getSnapshot() {
  return state;
}

function clearTracker() {
  if (rafId !== null) {
    cancelAnimationFrame(rafId);
    rafId = null;
  }
}

function startTracker() {
  clearTracker();
  const tick = () => {
    if (audio) {
      let level = 0;
      if (analyser && freqData) {
        analyser.getByteFrequencyData(freqData as unknown as Uint8Array<ArrayBuffer>);
        let sum = 0;
        for (let i = 0; i < freqData.length; i++) sum += freqData[i];
        level = Math.min(1, sum / freqData.length / 180);
      }
      setState({
        currentTime: audio.currentTime,
        duration: audio.duration || state.duration,
        level,
      });
    }
    rafId = requestAnimationFrame(tick);
  };
  rafId = requestAnimationFrame(tick);
}

function setupAnalyser(el: HTMLAudioElement) {
  try {
    if (!audioCtx) {
      const Ctx =
        (window as unknown as { AudioContext?: typeof AudioContext; webkitAudioContext?: typeof AudioContext }).AudioContext ||
        (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
      if (!Ctx) return;
      audioCtx = new Ctx();
    }
    if (audioCtx.state === "suspended") void audioCtx.resume();
    sourceNode = audioCtx.createMediaElementSource(el);
    analyser = audioCtx.createAnalyser();
    analyser.fftSize = 128;
    analyser.smoothingTimeConstant = 0.75;
    sourceNode.connect(analyser);
    analyser.connect(audioCtx.destination);
    freqData = new Uint8Array(analyser.frequencyBinCount);
  } catch (e) {
    // Analyser optional — playback still works
    console.warn("Audio analyser unavailable", e);
  }
}

function teardown() {
  clearTracker();
  if (audio) {
    audio.pause();
    audio.src = "";
    audio = null;
  }
  if (sourceNode) {
    try {
      sourceNode.disconnect();
    } catch {
      /* noop */
    }
    sourceNode = null;
  }
  if (analyser) {
    try {
      analyser.disconnect();
    } catch {
      /* noop */
    }
    analyser = null;
  }
  freqData = null;
  if (currentUrl) {
    URL.revokeObjectURL(currentUrl);
    currentUrl = null;
  }
}

async function play(text: string, key: string) {
  if (!text?.trim()) return;

  // Resume same track if paused
  if (state.activeKey === key && state.status === "paused" && audio) {
    await audio.play();
    setState({ status: "playing" });
    startTracker();
    return;
  }

  // Pause same track if playing
  if (state.activeKey === key && state.status === "playing" && audio) {
    audio.pause();
    clearTracker();
    setState({ status: "paused" });
    return;
  }

  // New track — teardown previous
  teardown();
  setState({
    status: "loading",
    activeKey: key,
    activeText: text,
    duration: 0,
    currentTime: 0,
    level: 0,
  });

  try {
    const res = await fetch("/api/tts", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    if (!res.ok) {
      const errText = await res.text();
      const isQuota = /quota_exceeded|quota of/i.test(errText) || res.status === 401;
      throw new Error(isQuota ? "QUOTA" : errText || `TTS failed (${res.status})`);
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    currentUrl = url;
    const a = new Audio(url);
    a.crossOrigin = "anonymous";
    audio = a;
    setupAnalyser(a);
    a.onloadedmetadata = () => {
      setState({ duration: a.duration });
    };
    a.onended = () => {
      clearTracker();
      teardown();
      setState({
        status: "idle",
        activeKey: null,
        activeText: "",
        currentTime: 0,
        duration: 0,
        level: 0,
      });
    };
    a.onerror = () => {
      teardown();
      setState({ status: "idle", activeKey: null, level: 0 });
    };
    await a.play();
    setState({ status: "playing" });
    startTracker();
  } catch (err) {
    console.error("TTS error:", err);
    teardown();
    setState({ status: "idle", activeKey: null, activeText: "", level: 0 });
    const msg = err instanceof Error ? err.message : "Unknown error";
    if (msg === "QUOTA") {
      toast.error("Voice service is out of credits", {
        description: "Audio narration is temporarily unavailable. All other checks still work normally.",
        duration: 5000,
      });
    } else {
      toast.error("Couldn't play audio", {
        description: "Please try again in a moment.",
        duration: 4000,
      });
    }
  }
}

function pause() {
  if (audio && state.status === "playing") {
    audio.pause();
    clearTracker();
    setState({ status: "paused" });
  }
}

function stop() {
  teardown();
  setState({
    status: "idle",
    activeKey: null,
    activeText: "",
    currentTime: 0,
    duration: 0,
    level: 0,
  });
}

export function useTtsPlayer() {
  const snap = useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
  return {
    ...snap,
    play,
    pause,
    stop,
  };
}
