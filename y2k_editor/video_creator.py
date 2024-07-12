import cv2
from moviepy.editor import VideoFileClip, AudioFileClip, ImageClip, AudioClip
import numpy as np
from moviepy.video.fx import all as vfx
from moviepy.editor import concatenate_videoclips
import subprocess
import os

def create_transition(input_video1, input_video2, transition, output_video, duration, offset):
    print("cr8 trns")
    command = [
        "ffmpeg",
        '-i', input_video1,
        '-i', input_video2,
        '-filter_complex', f'xfade=transition={transition}:duration={duration}:offset={offset}',
        output_video
    ]
    subprocess.run(command)
    
def renderVideo(image_list, audio , durations, transitions, quality, fps):
    clips=[]
    # Set a common size for all images
    quality = tuple(quality)
    if quality==(1920, 1080):
        common_size = (1920, 1080)
    elif quality==(640, 360):
        common_size = (640, 360)
    elif quality==(3840, 2160):
        common_size = (3840, 2160)
    if quality==(1280, 720):
        common_size = (1280, 720)
    
    j=0
    k=0
    # Read each image using cv2, resize, and append to the frame list
    for i, image in enumerate(image_list):
        imagebytearr = bytearray(image)
        image_np = np.asarray(imagebytearr, dtype=np.uint8)
        img = cv2.imdecode(image_np, cv2.IMREAD_COLOR)

        if img is not None:
            # Calculate the scale factor to fit the image within the common size
            scale_factor = min(common_size[0] / img.shape[1], common_size[1] / img.shape[0])

            # Resize the image while maintaining its aspect ratio. Convert the color from RGB to BGR
            img = cv2.resize(img, None, fx=scale_factor, fy=scale_factor)
            img = cv2.cvtColor(img, cv2.COLOR_RGB2BGR)

            # Create a black image of the common size. Convert the color from RGB to BGR
            black_img = np.zeros((common_size[1], common_size[0], 3), dtype=np.uint8)
            img_bgr = cv2.cvtColor(black_img, cv2.COLOR_RGB2BGR)

            # Calculate the position to place the original image
            x_offset = (common_size[0] - img.shape[1]) // 2
            y_offset = (common_size[1] - img.shape[0]) // 2

            # Place the original image on the black image
            img_bgr[y_offset:y_offset+img.shape[0], x_offset:x_offset+img.shape[1]] = img

            video_clip = ImageClip(img_bgr, duration=durations[i])
            
            
            # bgclip = ColorClip(common_size, (0, 0, 0), duration=durations[i])
            # imclip = ImageClip(img, duration=durations[i])
            # video_clip = CompositeVideoClip([bgclip, imclip.set_position((x_offset, y_offset))], size=common_size)
            
            if transitions[i] !="None":
                video_clip.write_videofile(f"temp/clip{k}.mp4", codec="libx264", audio=True, fps=fps)
                if j==0:
                    vid=VideoFileClip(f"temp/clip{k}.mp4")
                    clips.append(vid)
                    k+=1
                else:
                    create_transition(f"temp/clip{k-1}.mp4", f"temp/clip{k}.mp4", transitions[i], f"temp/output_video{k}.mp4", 1, 0)
                    vid=VideoFileClip(f"temp/output_video{k}.mp4")
                    clips.append(vid)
                    k+=1
            else:
                clips.append(video_clip)
            j+=durations[i]
            # video_clip.write_videofile(f"output_video{i}.mp4", codec="libx264", audio=True, fps=fps)
        else:
            print("Error decoding image")

    # Concatenate all the clips
    final_clip = concatenate_videoclips(clips)

    if audio:  # Check if audio data is provided
        with open('temp/audiofile.mp3', 'wb') as f:
            f.write(audio)
        audio_clip = AudioFileClip('temp/audiofile.mp3')
        if final_clip.duration < audio_clip.duration:
            audio_clip = audio_clip.subclip(0, final_clip.duration)
        final_clip = final_clip.set_audio(audio_clip)

    # Write the final video file
    final_clip.write_videofile("temp/output_video.mp4", codec="libx264", audio=True, fps=fps)
    
    for clip in clips:
        clip.close()
    
    if audio:
        audio_clip.close()
    
    final_clip.close()

    if transitions!="None":
        try: os.remove("temp/clip0.mp4")
        except Exception as e: print(f"-- Exception: {e}")
        
        for i in range(1,k):
            try: os.remove(f"temp/clip{i}.mp4")
            except Exception as e: print(f"-- Exception: {e}")

            try: os.remove(f"temp/output_video{i}.mp4")
            except Exception as e: print(f"-- Exception: {e}")
    
    with open("temp/output_video.mp4", "rb") as f:
        video = f.read()
    
    try: os.remove("temp/audiofile.mp3")
    except Exception as e: print(f"-- Exception: {e}")
    try: os.remove("temp/output_video.mp4")
    except Exception as e: print(f"-- Exception: {e}")
    
    return video


"""
if __name__ == '__main__':
    imagenames = [
        'test/img1.png',
        'test/img2.png',
        'test/img3.png',
        'test/img4.png',
        'test/img5.jpg',
        'test/img6.jpg'
        ]
    
    images = []
    
    for filep in imagenames:
        with open(filep, 'rb') as f:
            img = f.read()
        images.append(img)
    
    with open('test/audio1.mp3', 'rb') as f:
        audio = f.read()
    
    image_durations = [5, 5, 6, 6, 5, 4, 5]
    transitions = ['pixelize', 'fade', 'distance', 'fade', 'distance', 'pixelize', 'fade']
    resolution = [1920, 1080]
    fps = 24
    
    output = renderVideo(images, audio, image_durations, transitions, resolution, fps)
    
    with open('temp/meravideo.mp4', 'wb') as f:
        f.write(output)
# """
