cmake_minimum_required(VERSION 2.4)
project(DefaultSamples)

# Common file parsers
file(GLOB FILE_PARSER_CPP_FILES
     "${PROJECT_SOURCE_DIR}/../common/file_parser/helper_h264_parser.cpp")

# Build sample_send_h264_dual_stream
file(GLOB SAMPLE_SEND_H264_DUAL_STREAM_CPP_FILES
     "${PROJECT_SOURCE_DIR}/sample_send_h264_dual_stream.cpp"
     "${PROJECT_SOURCE_DIR}/../common/*.cpp")
add_executable(sample_send_h264_dual_stream ${SAMPLE_SEND_H264_DUAL_STREAM_CPP_FILES}
                                    ${FILE_PARSER_CPP_FILES})

