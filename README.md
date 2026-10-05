# Football SIEM

월드컵 빌드데이(2026-06-28)에서 만든 프로젝트예요. 실시간 축구 경기 데이터를 보안 로그처럼 다뤄서, 경기 흐름의 이상 징후를 SIEM 콘솔처럼 보여줘요.

![screenshot](스크린샷%202026-06-28%2022.08.34.png)

## 구성

- `app.py`: FastAPI 백엔드. 경기 스냅샷을 주기적으로 가져와 이상 징후를 탐지해요.
- `index.html`: SIEM 스타일 대시보드 (`/state` 폴링, `/start`로 데모 시작).
- `Football_SIEM_5slide.pptx`: 5장짜리 발표 자료.
- 시연 영상은 용량 때문에 저장소 대신 Release에 첨부했어요.

## 실행

```bash
pip install -r requirements.txt
python app.py   # http://localhost:8000
```

| 환경 변수 | 기본값 | 설명 |
|---|---|---|
| `SOURCE` | `mock` | `mock`(가상 경기) 또는 `espn`(ESPN 공개 API) |
| `ESPN_LEAGUE` | `fifa.world` | ESPN 리그 코드 |
| `EVENT_ID` | (비어 있음) | 특정 경기 ID |
| `POLL_SECONDS` | `4` | 폴링 간격(초) |
