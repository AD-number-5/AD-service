FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd -r -m -d /home/user -s /usr/sbin/nologin user

WORKDIR /home/user/app

COPY ./requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p uploaded static media \
    && chmod 750 entrypoint.sh \
    && chown -R user:user /home/user/app

USER user

ENTRYPOINT ["./entrypoint.sh"]
