CUR_PATH := $(shell pwd)
 
SRC_FOLDER := $(shell find $(CUR_PATH) -maxdepth 1 -type d)
BASE_SRC_FOLDER := $(basename $(patsubst $(CUR_PATH)/%, %, $(SRC_FOLDER)))
BASE_SRC_FOLDER := $(filter-out $(CUR_PATH), $(BASE_SRC_FOLDER))
BASE_SRC_FOLDER := $(filter-out lib, $(BASE_SRC_FOLDER))
BASE_SRC_FOLDER := $(filter-out obj, $(BASE_SRC_FOLDER))
 
default:
	@for dir in ${BASE_SRC_FOLDER}; do make -C $(CUR_PATH)/$$dir ||exit; done
	@echo build project done!
 
clean:
	@for dir in ${BASE_SRC_FOLDER}; do make -C $(CUR_PATH)/$$dir clean ||exit; done
	@echo clean project done!

.PHONY: default clean
