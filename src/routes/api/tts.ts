import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/tts")({
  
  server: {
    handlers: {
      POST: async ({ request }: { request: Request }) => {
        const apiKey = process.env.ELEVENLABS_API_KEY;
        if (!apiKey) {
          return new Response("ELEVENLABS_API_KEY is not configured", { status: 500 });
        }

        let body: { text?: string; voiceId?: string };
        try {
          body = await request.json();
        } catch {
          return new Response("Invalid JSON body", { status: 400 });
        }

        const text = (body.text ?? "").toString().trim();
        if (!text) {
          return new Response("Missing text", { status: 400 });
        }
        const safeText = text.length > 9500 ? text.slice(0, 9500) : text;

        const voiceId = body.voiceId ?? "EXAVITQu4vr4xnSDxMaL"; // Sarah — friendly, clear

        const res = await fetch(
          `https://api.elevenlabs.io/v1/text-to-speech/${voiceId}?output_format=mp3_44100_128`,
          {
            method: "POST",
            headers: {
              "xi-api-key": apiKey,
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              text: safeText,
              model_id: "eleven_turbo_v2_5",
              voice_settings: {
                stability: 0.5,
                similarity_boost: 0.75,
                style: 0.3,
                use_speaker_boost: true,
              },
            }),
          },
        );

        if (!res.ok) {
          const err = await res.text();
          return new Response(`TTS failed [${res.status}]: ${err}`, { status: 502 });
        }

        const audio = await res.arrayBuffer();
        return new Response(audio, {
          status: 200,
          headers: {
            "Content-Type": "audio/mpeg",
            "Cache-Control": "no-store",
          },
        });
      },
    },
  },
});
