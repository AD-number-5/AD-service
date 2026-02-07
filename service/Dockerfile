FROM ubuntu:latest

RUN apt-get update \
	&& apt-get install -y python3 python3-pip python3-venv \
	&& rm -rf /var/lib/apt/lists/* \
	&& useradd -r -m -d /home/user -s /usr/sbin/nologin user

WORKDIR /home/user/app

COPY ./app /home/user/app

RUN python3 -m venv /home/user/venv \
	&& /home/user/venv/bin/pip install --no-cache-dir -r /home/user/app/requirements.txt \
	&& chmod 750 /home/user/app/entrypoint.sh \
	&& chown -R user:user /home/user/app /home/user/venv

USER user

ENV PATH="/home/user/venv/bin:$PATH"

ENTRYPOINT ["/home/user/app/entrypoint.sh"]
