include(FetchContent)

FetchContent_Declare(FugueSchema
  URL https://github.com/fugue-re/fugue-db-schema/archive/master.zip
)
if(NOT fugueschema_POPULATED)
  FetchContent_Populate(FugueSchema)
  set(fugueschema_SOURCE_DIR ${fugueschema_SOURCE_DIR} PARENT_SCOPE)
endif()

FetchContent_Declare(FlatBuffers
  URL https://github.com/google/flatbuffers/archive/v2.0.0.zip
)
FetchContent_MakeAvailable(FlatBuffers)
