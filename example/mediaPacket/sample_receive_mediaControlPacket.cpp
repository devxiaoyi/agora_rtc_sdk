//  Agora RTC/MEDIA SDK
//
//  Created by Jay Zhang in 2020-04.
//  Copyright (c) 2020 Agora.io. All rights reserved.
//

#include <time.h>

#include <csignal>
#include <cstring>
#include <sstream>
#include <string>
#include <thread>

#include "IAgoraService.h"
#include "NGIAgoraRtcConnection.h"
#include "common/log.h"
#include "common/opt_parser.h"
#include "common/sample_common.h"
#include "common/sample_local_user_observer.h"

#include <ctime>
#include <iostream>
using namespace std;

string now() {
  time_t t = time(0);
  char buffer[9] = {0};
  strftime(buffer, 9, "%H:%M:%S", localtime(&t));
  return string(buffer);
}

struct SampleOptions {
  std::string appId;
  std::string channelId;
  std::string userId;
  std::string remoteUserId;
};

class MediaPacketReceiver : public agora::rtc::IMediaControlPacketReceiver {
 public:
  // agora::rtc::IMediaControlPacketReceiver
  bool onMediaControlPacketReceived(uid_t uid, const uint8_t* packet, size_t length) override;
};

bool MediaPacketReceiver::onMediaControlPacketReceived(uid_t uid, const uint8_t* packet, size_t length) {
  std::cout << "Times passed in seconds: " << now() << "length is :" << length << ", buf is :";
  for (int i = 0; i < length; i++) {
    std::cout << packet[i];
  }
  std::cout << std::endl;
  return true;
}

static bool exitFlag = false;
static void SignalHandler(int sigNo) { exitFlag = true; }

int main(int argc, char* argv[]) {
  SampleOptions options;
  opt_parser optParser;

  optParser.add_long_opt("token", &options.appId, "The token for authentication");
  optParser.add_long_opt("channelId", &options.channelId, "Channel Id");
  optParser.add_long_opt("userId", &options.userId, "User Id / default is 0");
  
  if ((argc <= 1) || !optParser.parse_opts(argc, argv)) {
    std::ostringstream strStream;
    optParser.print_usage(argv[0], strStream);
    std::cout << strStream.str() << std::endl;
    return -1;
  }

  if (options.appId.empty()) {
    AG_LOG(ERROR, "Must provide appId!");
    return -1;
  }

  if (options.channelId.empty()) {
    AG_LOG(ERROR, "Must provide channelId!");
    return -1;
  }

  std::signal(SIGQUIT, SignalHandler);
  std::signal(SIGABRT, SignalHandler);
  std::signal(SIGINT, SignalHandler);

  // Create Agora service
  auto service = createAndInitAgoraService(false, true, true);
  if (!service) {
    AG_LOG(ERROR, "Failed to creating Agora service!");
  }

  // Create Agora connection
  agora::rtc::RtcConnectionConfiguration ccfg;
  ccfg.clientRoleType = agora::rtc::CLIENT_ROLE_BROADCASTER;
  ccfg.autoSubscribeAudio = false;
  ccfg.autoSubscribeVideo = false;
  ccfg.enableAudioRecordingOrPlayout = false;  // Subscribe audio but without playback

  agora::agora_refptr<agora::rtc::IRtcConnection> connection = service->createRtcConnection(ccfg);
  if (!connection) {
    AG_LOG(ERROR, "Failed to creating Agora connection!");
    return -1;
  }

  // Connect to Agora channel
  if (connection->connect(options.appId.c_str(), options.channelId.c_str(), options.userId.c_str())) {
    AG_LOG(ERROR, "Failed to connect to Agora channel!");
    return -1;
  }

  // Register audio frame observer to receive audio stream
  MediaPacketReceiver Res;
  connection->getLocalUser()->registerMediaControlPacketReceiver(&Res);

  // Start receiving incoming media data
  AG_LOG(INFO, "Start receiving audio & video data ...");

  // Periodically check exit flag
  while (!exitFlag) {
    usleep(10 * 1000);
  }

  // Disconnect from Agora channel
  if (connection->disconnect()) {
    AG_LOG(ERROR, "Failed to disconnect from Agora channel!");
    return -1;
  }
  AG_LOG(INFO, "Disconnected from Agora channel successfully");

  // Destroy Agora connection and related resources
  connection->getLocalUser()->unregisterMediaControlPacketReceiver(&Res);

  connection = nullptr;

  // Destroy Agora Service
  service->release();
  service = nullptr;

  return 0;
}
