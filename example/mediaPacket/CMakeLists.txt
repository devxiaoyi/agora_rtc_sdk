project(DefaultSamples)

# Common file parsers
file(GLOB FILE_PARSER_CPP_FILES
     "${PROJECT_SOURCE_DIR}/../common/file_parser/helper_h264_parser.cpp")

# Build SendmediaControlPacket
file(GLOB SAMPLE_SEND_H264_PCM_CPP_FILES
     "${PROJECT_SOURCE_DIR}/sample_send_mediaControlPacket.cpp"
     "${PROJECT_SOURCE_DIR}/../common/*.cpp")
add_executable(sample_send_mediaControlPacket ${SAMPLE_SEND_H264_PCM_CPP_FILES}
                                    ${FILE_PARSER_CPP_FILES})

# Build sample_receive_mediaControlPacket
file(GLOB SAMPLE_RECEIVE_H264_PCM_CPP_FILES
     "${PROJECT_SOURCE_DIR}/sample_receive_mediaControlPacket.cpp"
     "${PROJECT_SOURCE_DIR}/../common/*.cpp")
add_executable(sample_receive_mediaControlPacket ${SAMPLE_RECEIVE_H264_PCM_CPP_FILES})

