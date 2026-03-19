NAME    = ft_nmap

CC      = cc
CFLAGS  ?= -Wall -Wextra -Werror -Iinclude
LDFLAGS ?= -lpcap -lpthread

SRC_DIR = src
OBJ_DIR = obj

SRCS =	$(SRC_DIR)/main.c \
		$(SRC_DIR)/args.c \
		$(SRC_DIR)/ports.c \
		$(SRC_DIR)/targets.c \
		$(SRC_DIR)/threadpool.c \
    	$(SRC_DIR)/scan.c \
		$(SRC_DIR)/services.c \
		$(SRC_DIR)/output.c \
		$(SRC_DIR)/resolve.c


OBJS = $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

.PHONY: all clean fclean re

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(NAME) $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

clean:
	rm -rf $(OBJ_DIR)

fclean: clean
	rm -f $(NAME)

re: fclean all