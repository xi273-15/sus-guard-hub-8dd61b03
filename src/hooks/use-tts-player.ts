import { useSyncExternalStore } from "react";

type Status = "idle" | "loading" | "playing" | "paused";

type State = {
  status: Status;
  activeKey: string | null;
  activeText: string;
  duration: number;
  currentTime: number;
};

const listeners = new Set<() => void>();
let state: State = {
  status: "idle",
  activeKey: null,
  activeText: "",
  duration: 0,
  currentTime: 0,
};
let audio: HTMLAudioElement | null = null;
let currentUrl: string | null = null;
let rafId: number | null = null;

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
      setState({ currentTime: audio.currentTime, duration: audio.duration || state.duration });
    }
    rafId = requestAnimationFrame(tick);
  };
  rafId = requestAnimationFrame(tick);
}

function teardown() {
  clearTracker();
  if (audio) {
    audio.pause();
    audio.src = "";
    audio = null;
  }
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
  setState({ status: "loading", activeKey: key, activeText: text, duration: 0, currentTime: 0 });

  try {
    const res = await fetch("/api/tts", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    if (!res.ok) throw new Error(await res.text());
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    currentUrl = url;
    const a = new Audio(url);
    audio = a;
    a.onloadedmetadata = () => {
      setState({ duration: a.duration });
    };
    a.onended = () => {
      clearTracker();
      teardown();
      setState({ status: "idle", activeKey: null, activeText: "", currentTime: 0, duration: 0 });
    };
    a.onerror = () => {
      teardown();
      setState({ status: "idle", activeKey: null });
    };
    await a.play();
    setState({ status: "playing" });
    startTracker();
  } catch (err) {
    console.error("TTS error:", err);
    teardown();
    setState({ status: "idle", activeKey: null, activeText: "" });
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
  setState({ status: "idle", activeKey: null, activeText: "", currentTime: 0, duration: 0 });
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
