"""
Convert animated WebP recordings to MP4 (H.264, yuv420p) with high quality.
"""
import os
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from PIL import Image, ImageSequence
import numpy as np
# pyrefly: ignore [missing-import]
import imageio

def convert_webp_to_mp4(input_path, output_path, fps=10):
    print(f"[*] Reading frames from {input_path}...")
    img = Image.open(input_path)
    
    durations = []
    frames = []
    
    for frame in ImageSequence.Iterator(img):
        rgb_frame = Image.new("RGB", frame.size, (11, 15, 25))
        if frame.mode in ("RGBA", "LA") or (frame.mode == "P" and "transparency" in frame.info):
            rgb_frame.paste(frame.convert("RGBA"), mask=frame.convert("RGBA").split()[3])
        else:
            rgb_frame.paste(frame.convert("RGB"))
        
        frames.append(np.array(rgb_frame))
        durations.append(frame.info.get("duration", 100))
    
    if not frames:
        print(f"[!] No frames found in {input_path}")
        return False
    
    avg_duration_ms = sum(durations) / len(durations) if durations else 100
    calculated_fps = round(1000.0 / avg_duration_ms, 2) if avg_duration_ms > 0 else fps
    print(f"[+] Extracted {len(frames)} frames. Average frame time: {avg_duration_ms:.1f}ms (~{calculated_fps} FPS)")
    
    print(f"[*] Encoding MP4 video to {output_path} (codec=libx264, pix_fmt=yuv420p)...")
    writer = imageio.get_writer(
        output_path,
        format="FFMPEG",
        mode="I",
        fps=calculated_fps,
        codec="libx264",
        pixelformat="yuv420p",
        quality=8,
        ffmpeg_params=["-preset", "medium", "-crf", "18"]
    )
    
    for idx, f in enumerate(frames):
        writer.append_data(f)
            
    writer.close()
    file_size_mb = os.path.getsize(output_path) / (1024 * 1024)
    print(f"[+] Successfully created MP4: {output_path} ({file_size_mb:.2f} MB)")
    return True

if __name__ == "__main__":
    recordings_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "docs", "media", "recordings"))
    
    live_test_webp = os.path.join(recordings_dir, "aegis_ai_live_system_test.webp")
    live_test_mp4 = os.path.join(recordings_dir, "aegis_ai_live_system_test.mp4")
    
    if os.path.exists(live_test_webp):
        convert_webp_to_mp4(live_test_webp, live_test_mp4)
