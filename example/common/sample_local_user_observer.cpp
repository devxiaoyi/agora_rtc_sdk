//  Agora RTC/MEDIA SDK
//
//  Created by Pengfei Han in 2020-03.
//  Copyright (c) 2020 Agora.io. All rights reserved.
//

#include "sample_local_user_observer.h"

#include "log.h"

SampleLocalUserObserver::SampleLocalUserObserver(agora::rtc::ILocalUser* local_user)
    : local_user_(local_user) {
  local_user_->registerLocalUserObserver(this);
}

SampleLocalUserObserver::~SampleLocalUserObserver() {
  local_user_->unregisterLocalUserObserver(this);
}

agora::rtc::ILocalUser* SampleLocalUserObserver::GetLocalUser() { return local_user_; }

void SampleLocalUserObserver::PublishAudioTrack(
    agora::agora_refptr<agora::rtc::ILocalAudioTrack> audioTrack) {
  local_user_->publishAudio(audioTrack);
}

void SampleLocalUserObserver::PublishVideoTrack(
    agora::agora_refptr<agora::rtc::ILocalVideoTrack> videoTrack) {
  local_user_->publishVideo(videoTrack);
}

void SampleLocalUserObserver::UnpublishAudioTrack(
    agora::agora_refptr<agora::rtc::ILocalAudioTrack> audioTrack) {
  local_user_->unpublishAudio(audioTrack);
}

void SampleLocalUserObserver::UnpublishVideoTrack(
    agora::agora_refptr<agora::rtc::ILocalVideoTrack> videoTrack) {
  local_user_->unpublishVideo(videoTrack);
}

void SampleLocalUserObserver::onUserAudioTrackSubscribed(
    agora::user_id_t userId, agora::agora_refptr<agora::rtc::IRemoteAudioTrack> audioTrack) {
  std::lock_guard<std::mutex> _(observer_lock_);
  remote_audio_track_ = audioTrack;
  if (remote_audio_track_ && media_packet_receiver_) {
    remote_audio_track_->registerMediaPacketReceiver(media_packet_receiver_);
  }
  if (remote_audio_track_ && audio_frame_observer_) {
    local_user_->registerAudioFrameObserver(audio_frame_observer_);
  }
}

void SampleLocalUserObserver::onUserVideoTrackSubscribed(
    agora::user_id_t userId, agora::rtc::VideoTrackInfo trackInfo,
    agora::agora_refptr<agora::rtc::IRemoteVideoTrack> videoTrack) {
  AG_LOG(INFO, "onUserVideoTrackSubscribed: userId %s, codecType %d, encodedFrameOnly %d", userId,
         trackInfo.codecType, trackInfo.encodedFrameOnly);
  std::lock_guard<std::mutex> _(observer_lock_);
  remote_video_track_ = videoTrack;
  if (remote_video_track_ && video_encoded_receiver_) {
    remote_video_track_->registerVideoEncodedImageReceiver(video_encoded_receiver_);
  }
  if (remote_video_track_ && media_packet_receiver_) {
    remote_video_track_->registerMediaPacketReceiver(media_packet_receiver_);
  }
  if (remote_video_track_ && video_frame_observer_) {
    remote_video_track_->addRenderer(video_frame_observer_);
  }
}

void SampleLocalUserObserver::onUserInfoUpdated(agora::user_id_t userId,
                                                ILocalUserObserver::USER_MEDIA_INFO msg, bool val) {
  AG_LOG(INFO, "onUserInfoUpdated: userId %s, msg %d, val %d", userId, msg, val);
}

void SampleLocalUserObserver::onUserAudioTrackStateChanged(
    agora::user_id_t userId, agora::agora_refptr<agora::rtc::IRemoteAudioTrack> audioTrack,
    agora::rtc::REMOTE_AUDIO_STATE state, agora::rtc::REMOTE_AUDIO_STATE_REASON reason,
    int elapsed) {
  AG_LOG(INFO, "onUserAudioTrackStateChanged: userId %s, state %d, reason %d", userId, state,
         reason);
}

void SampleLocalUserObserver::onIntraRequestReceived() {
  AG_LOG(INFO, "onIntraRequestReceived");
}
