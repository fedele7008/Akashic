FROM golang:latest

WORKDIR /app

RUN apt-get update
RUN apt-get install -y sudo
RUN sudo apt-get update -y && sudo apt-get upgrade -y
RUN sudo apt-get install -y bash-completion
RUN echo "source /etc/profile.d/bash_completion.sh" >> /root/.bashrc

COPY ./go.mod ./go.sum ./
RUN go mod download

COPY . .
RUN go build -v -o /usr/local/bin/akashic-cli /app/cmd/akashic-cli
RUN chmod +x /usr/local/bin/akashic-cli
RUN akashic-cli completion bash > /etc/bash_completion.d/akashic-cli

ENTRYPOINT ["/bin/bash"]
