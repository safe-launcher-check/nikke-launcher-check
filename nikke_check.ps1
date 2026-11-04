# NIKKE PC launcher compromise (2026-11) - READ-ONLY indicator checker v0.3.1
# Deletes nothing, changes nothing, closes nothing, blocks nothing, sends nothing. Warnings only.
# Run without admin rights, on the Windows account that used NIKKE.
# Indicators: MotherSphere public report, 2026-11-04 02:00 GMT revision.
# Exit codes: 0 = no known traces, 1 = warning, 2 = danger, 3 = limited result

[CmdletBinding()]
param(
    [string[]]$NikkePath = @(),
    [string]$ReportDir = '',
    [switch]$NoPrompt,
    [switch]$DeepScan,
    [switch]$AllUsers,
    [string[]]$SearchRoot = @(),
    [int]$ScanSeconds = 0,
    [ValidateSet('', 'ko', 'en', 'ja', 'zh-Hant', 'zh-Hans')][string]$Language = ''
)

$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }

$script:Strings = @{
  'ko' = @{
    title = '=== 니케 PC 런처 감염 흔적 점검 (읽기 전용) ==='
    intro = '아무것도 삭제하거나 변경하지 않습니다. 설치 폴더를 찾는 데 1~2분 걸릴 수 있습니다.'
    deep = '설치 폴더 정밀 탐색 중입니다. 드라이브 크기에 따라 몇 분 걸릴 수 있습니다.'
    ask = '니케 설치 폴더를 찾지 못했습니다. 경로를 입력하세요 (없으면 그냥 Enter)'
    badpath = '입력한 경로에 Launcher 폴더가 없어 건너뜁니다.'
    i_scan = '설치 폴더 탐색'
    scan_cut = '{0}초 제한에 걸려 탐색을 일부만 했습니다. 니케가 있다면 -NikkePath로 경로를 지정하거나 -DeepScan을 사용하세요.'
    L_danger = '위험'
    L_warn = '주의'
    L_unknown = '확인불가'
    L_ok = '정상'
    i_run = '런처 실행'
    running = '{0} 실행 중. 이 도구는 종료하지 않으니 트레이까지 확인해 직접 닫으세요.'
    notrunning = '니케 런처 관련 프로세스 없음'
    i_log = '런처 로그'
    log_hit = '{0} : 에이전트 실행 기록 ({1})'
    log_start = '{0} : startup already in progress 발견. 에이전트 시작 기록은 없고, 이 문구만으로는 판단할 수 없음'
    log_ok = '{0} : 실행 기록 없음'
    log_none = '{0} 없음'
    log_noroot = '설치 폴더를 찾지 못해 debug.log를 검사하지 못함 (삭제했거나 다른 위치에 설치)'
    i_pcname = '기록된 PC 이름'
    pc_same = '로그의 PC 이름이 이 PC와 일치 (이름은 표시하지 않음)'
    pc_diff = '로그의 PC 이름이 이 PC와 다름. PC 이름 변경 또는 다른 PC에서 복사한 폴더일 수 있음 (이름은 표시하지 않음)'
    i_dl = '다운로드 로그'
    dl_hit = '{0} : 악성 페이로드 다운로드 기록 ({1})'
    dl_ok = '{0} : 기록 없음'
    i_payload = '페이로드 파일'
    pl_hash = '{0} : 공개된 페이로드 해시와 일치'
    pl_size = '{0} : 페이로드와 크기가 같음(205,135바이트). 빌드가 여러 개라 해시가 달라도 안전하다는 뜻은 아님'
    i_state = '에이전트 상태값'
    st_hit = '{0} Local Storage에서 k2f.agent 발견 (내용은 표시하지 않음)'
    st_ok = '{0} Local Storage에 k2f.agent 없음 (압축된 .ldb의 옛 값은 못 볼 수 있음)'
    st_none = '{0} Local Storage 없음'
    i_loader = '로더 흔적'
    ld_hit = '{0} 캐시에서 로더 흔적 발견. 공격자 서버에 접속한 흔적이며, 에이전트 실행 여부는 다른 항목으로 판단'
    ld_ok = '{0} 코드 캐시에 로더 흔적 없음'
    i_cache = '변조 파일 캐시'
    ca_hit = '{0} HTTP 캐시에 변조 JS 파일이 남아 있음. 다음 실행 전 tbs_cache 삭제 필요'
    ca_ok = '{0} HTTP 캐시에 알려진 변조 파일 없음'
    i_dll = '브라우저 DLL'
    i_baddll = '브라우저 악성 DLL'
    dll_signed = '{0} : Google 또는 Microsoft 유효 서명이 있어 악성 판정은 하지 않음. 위치만 수동 확인 필요'
    dll_other = '{0} : 같은 이름의 서명 없는 파일. 알려진 경로는 아니므로 추가 확인 필요'
    i_hexdir = '브라우저 해시 폴더'
    hex_only = '{0} : DLL 없이 64자리 폴더만 남아 있음. 삭제된 흔적일 수 있음'
    dll_ok = 'AppData에서 해당 DLL 없음, 브라우저 프로필 {0}개 확인. PlatformExperienceHelper 폴더 자체는 정상. 사용자 지정 프로필 경로는 찾지 못할 수 있음'
    dll_noapp = 'AppData 경로를 찾지 못함'
    i_chromeold = 'Chrome 구버전 경로'
    old_hit = '{0} 존재. 서명 없는 파일이라 추가 확인 필요'
    i_reg = '레지스트리'
    reg_hit = '{0} 키 존재 (값이 비어 있어도 흔적임). {1}'
    reg_none = '연결 대상 없음'
    reg_file = '연결 파일 있음: {0}'
    reg_nofile = '연결 파일 없음: {0}'
    reg_other = '{0} 가 같은 이름의 DLL을 가리킴'
    reg_ok = 'HKCU CLSID 키 없음, 같은 DLL을 가리키는 COM 등록 없음'
    i_other = '다른 계정'
    other_ok = '로드된 계정 {0} 레지스트리 확인 (로그아웃한 계정은 확인하지 못함)'
    i_temp = '임시 파일'
    tmp_hit = 'TEMP에서 {0}개 발견: {1}'
    tmp_ok = 'k2f 임시 파일 없음 (악성코드가 사용 후 지우므로 없어도 안전 보장은 아님)'
    i_conn = '현재 연결'
    conn_hit = '공격자 서버 IP에 연결 중: {0}'
    conn_ok = '공격자 서버 IP 연결 없음'
    conn_na = '연결 정보를 확인할 수 없음'
    i_dns = 'DNS 캐시'
    dns_hit = '최근 조회 기록: {0}. insightjs.org는 제3자 경고 페이지이므로 그 도메인만 있으면 위험도가 낮음'
    dns_ok = 'insightjs 조회 기록 없음 (재부팅하면 지워짐)'
    i_read = '파일 읽기'
    read_err = '파일 {0}개를 읽지 못해 검사에서 빠짐'
    step_fail = '검사 실패: {0}'
    v_danger = '위험: 악성 에이전트가 이 PC에서 실행된 흔적이 있습니다.'
    v_warn = '주의: 실행 기록은 없지만 변조 파일이나 공격자 서버 접속 흔적이 있습니다.'
    v_fail = '판정 제한: 일부 검사를 끝내지 못했습니다. 아래 확인불가 항목을 확인하세요.'
    v_nolog = '판정 제한: 런처를 쓴 흔적은 있으나 debug.log가 없어 실행 기록을 확인하지 못했습니다.'
    v_none = '판정 제한: 이 Windows 계정에서 니케 PC 런처 사용 흔적을 찾지 못했습니다. 다른 계정이나 삭제된 설치는 확인하지 못합니다.'
    v_ok = '알려진 흔적 미발견: 안전하다는 뜻은 아닙니다.'
    r_title = '니케 PC 런처 감염 흔적 점검 결과'
    r_time = '점검 시각: {0}'
    r_dir = '설치 폴더: {0}'
    r_nodir = '찾지 못함'
    r_verdict = '판정: {0}'
    r_saved = '결과 파일: {0}'
    r_savefail = '결과 파일 저장 실패: {0}'
    r_mt = '기계 번역이 포함되어 있습니다. 오역은 GitHub Issues로 알려주세요.'
    d_head = '이 도구는 아무것도 변경하지 않았습니다. 다음 조치는 직접 하세요 (보고서 권고 순서).'
    d1 = '1. 런처를 닫거나 인터넷을 끊기'
    d2 = '2. HKCU 키 삭제 -> 재부팅 -> 64자리 폴더만 삭제 (PlatformExperienceHelper 폴더 전체와 HKLM 항목은 삭제 금지)'
    d_key = '   레지스트리 키: {0}'
    d_dir = '   폴더: {0}'
    d_file = '   파일: {0}'
    d3 = '3. 가장 안전한 방법은 Windows 재설치'
    d4 = '4. 깨끗한 다른 기기에서 니케 계정, 이메일 순으로 비밀번호 변경, 2단계 인증 설정, 모든 세션 로그아웃'
    d5 = '5. API 토큰, SSH 키, 개발자 자격증명 폐기 후 재발급'
    d6 = '6. 암호화폐 지갑은 새 시드의 새 지갑으로 이전'
    d7 = '백신 검사가 깨끗해도 제거를 보장하지 않습니다 (Defender 오프라인 검사가 DLL을 못 찾은 사례 보고).'
    n_head = '참고'
    n1 = '- 공개된 흔적만 검사합니다. 공격자가 흔적을 지웠거나 로그가 삭제됐으면 찾지 못합니다.'
    n2 = '- 2026년 10월 23일(GMT) 이후 런처를 실행했다면 주요 비밀번호 변경과 세션 로그아웃을 권장합니다.'
    n3 = '- 공식 조치 확인 전에는 런처를 열지 말고, 다시 열기 전 %APPDATA%\nikke_launcher\tbs_cache를 삭제하세요.'
  }
  'en' = @{
    title = '=== NIKKE PC launcher trace check (read-only) ==='
    intro = 'Nothing is deleted or changed. Finding the install folder may take 1-2 minutes.'
    deep = 'Deep-searching for the install folder. This may take a few minutes.'
    ask = 'NIKKE install folder not found. Enter its path (or just press Enter)'
    badpath = 'No Launcher folder at that path; skipping.'
    i_scan = 'Install folder search'
    scan_cut = 'Search stopped at the {0}-second limit. If NIKKE is installed, use -NikkePath or -DeepScan.'
    L_danger = 'DANGER'
    L_warn = 'WARNING'
    L_unknown = 'UNKNOWN'
    L_ok = 'OK'
    i_run = 'Launcher running'
    running = '{0} is running. This tool will not close it; close it yourself, including the system tray.'
    notrunning = 'No NIKKE launcher processes'
    i_log = 'Launcher log'
    log_hit = '{0} : agent execution records ({1})'
    log_start = '{0} : startup already in progress found. No agent start record; this line alone is not conclusive'
    log_ok = '{0} : no execution records'
    log_none = '{0} not found'
    log_noroot = 'Install folder not found, so debug.log was not checked (deleted or installed elsewhere)'
    i_pcname = 'Recorded PC name'
    pc_same = 'PC name in the log matches this PC (name not shown)'
    pc_diff = 'PC name in the log differs from this PC. It may have been renamed or the folder copied from another PC (name not shown)'
    i_dl = 'Download log'
    dl_hit = '{0} : malicious payload download records ({1})'
    dl_ok = '{0} : no records'
    i_payload = 'Payload file'
    pl_hash = '{0} : matches a published payload hash'
    pl_size = '{0} : same size as the payload (205,135 bytes). Several builds exist, so a different hash does not mean safe'
    i_state = 'Agent state'
    st_hit = 'k2f.agent found in {0} Local Storage (contents not shown)'
    st_ok = 'No k2f.agent in {0} Local Storage (older values in compressed .ldb may be missed)'
    st_none = '{0} Local Storage not found'
    i_loader = 'Loader trace'
    ld_hit = 'Loader trace in {0} cache. It shows contact with the attacker server; judge agent execution from the other items'
    ld_ok = 'No loader trace in {0} code cache'
    i_cache = 'Modified file cache'
    ca_hit = 'Modified JS files remain in {0} HTTP cache. Delete tbs_cache before the next launch'
    ca_ok = 'No known modified files in {0} HTTP cache'
    i_dll = 'Browser DLL'
    i_baddll = 'Malicious browser DLL'
    dll_signed = '{0} : valid Google or Microsoft signature, so not flagged as malicious. Check its location manually'
    dll_other = '{0} : unsigned file with the same name, not at the known path. Needs further checking'
    i_hexdir = 'Browser hash folder'
    hex_only = '{0} : 64-hex folder without the DLL. It may be a leftover'
    dll_ok = 'No such DLL in AppData; {0} browser profiles checked. The PlatformExperienceHelper folder itself is normal. Custom profile paths may be missed'
    dll_noapp = 'AppData path not found'
    i_chromeold = 'Chrome legacy path'
    old_hit = '{0} exists. Unsigned, so it needs further checking'
    i_reg = 'Registry'
    reg_hit = '{0} key exists (a trace even if its value is empty). {1}'
    reg_none = 'no target'
    reg_file = 'target exists: {0}'
    reg_nofile = 'target missing: {0}'
    reg_other = '{0} points to a DLL with the same name'
    reg_ok = 'No HKCU CLSID key and no COM entry pointing to the DLL'
    i_other = 'Other accounts'
    other_ok = 'Registry of loaded account {0} checked (signed-out accounts are not checked)'
    i_temp = 'Temp files'
    tmp_hit = '{0} found in TEMP: {1}'
    tmp_ok = 'No k2f temp files (the malware deletes them after use, so this proves nothing)'
    i_conn = 'Current connections'
    conn_hit = 'Connected to attacker server IP: {0}'
    conn_ok = 'No connection to attacker server IPs'
    conn_na = 'Connection information unavailable'
    i_dns = 'DNS cache'
    dns_hit = 'Recent lookups: {0}. insightjs.org is now a third-party warning page, so that domain alone is lower risk'
    dns_ok = 'No insightjs lookups (cleared on reboot)'
    i_read = 'File read'
    read_err = '{0} files could not be read and were skipped'
    step_fail = 'Check failed: {0}'
    v_danger = 'DANGER: traces show the malicious agent ran on this PC.'
    v_warn = 'WARNING: no execution records, but modified files or traces of contact with the attacker server exist.'
    v_fail = 'LIMITED: some checks did not finish. See the UNKNOWN items below.'
    v_nolog = 'LIMITED: the launcher was used, but without debug.log execution records could not be checked.'
    v_none = 'LIMITED: no NIKKE PC launcher use found on this Windows account. Other accounts and deleted installs cannot be checked.'
    v_ok = 'No known traces found. This does not mean you are safe.'
    r_title = 'NIKKE PC launcher trace check result'
    r_time = 'Checked at: {0}'
    r_dir = 'Install folder: {0}'
    r_nodir = 'not found'
    r_verdict = 'Result: {0}'
    r_saved = 'Report file: {0}'
    r_savefail = 'Could not save the report: {0}'
    r_mt = 'This text includes machine translation. Report errors via GitHub Issues.'
    d_head = 'This tool changed nothing. Take these steps yourself (order from the report).'
    d1 = '1. Close the launcher or disconnect from the internet'
    d2 = '2. Delete the HKCU key -> restart -> delete only the 64-hex folder (do NOT delete the whole PlatformExperienceHelper folder or the HKLM entry)'
    d_key = '   Registry key: {0}'
    d_dir = '   Folder: {0}'
    d_file = '   File: {0}'
    d3 = '3. Reinstalling Windows is the safest option'
    d4 = '4. From a clean device: change passwords (NIKKE, then email and others), enable 2FA, sign out of all sessions'
    d5 = '5. Revoke and reissue API tokens, SSH keys and developer credentials'
    d6 = '6. Move crypto funds to a new wallet with a new seed phrase'
    d7 = 'A clean antivirus scan does not guarantee removal (Defender Offline reportedly missed the DLL).'
    n_head = 'Notes'
    n1 = '- Only published traces are checked. Removed traces or deleted logs cannot be found.'
    n2 = '- If you ran the launcher after Oct 23, 2026 (GMT), changing key passwords and signing out of sessions is recommended.'
    n3 = '- Do not open the launcher until an official fix is confirmed, and delete %APPDATA%\nikke_launcher\tbs_cache before reopening it.'
  }
  'ja' = @{
    title = '=== NIKKE PCランチャー 感染痕跡チェック（読み取り専用） ==='
    intro = '何も削除・変更しません。インストールフォルダの検索に1～2分かかる場合があります。'
    deep = 'インストールフォルダを詳細検索中です。数分かかる場合があります。'
    ask = 'NIKKEのインストールフォルダが見つかりません。パスを入力してください（なければEnter）'
    badpath = 'そのパスにLauncherフォルダがないためスキップします。'
    i_scan = 'インストールフォルダ検索'
    scan_cut = '{0}秒の制限で検索を途中で終了しました。NIKKEがある場合は -NikkePath または -DeepScan を使ってください。'
    L_danger = '危険'
    L_warn = '注意'
    L_unknown = '確認不可'
    L_ok = '問題なし'
    i_run = 'ランチャー起動'
    running = '{0} が実行中です。このツールは終了させないので、トレイも確認してご自身で閉じてください。'
    notrunning = 'NIKKEランチャー関連のプロセスなし'
    i_log = 'ランチャーログ'
    log_hit = '{0} : エージェント実行の記録 ({1})'
    log_start = '{0} : startup already in progress を検出。エージェント開始の記録はなく、この文字列だけでは判断できません'
    log_ok = '{0} : 実行の記録なし'
    log_none = '{0} が見つかりません'
    log_noroot = 'インストールフォルダが見つからず debug.log を確認できません（削除済みまたは別の場所）'
    i_pcname = '記録されたPC名'
    pc_same = 'ログのPC名がこのPCと一致（名前は表示しません）'
    pc_diff = 'ログのPC名がこのPCと異なります。名前変更または別PCからのコピーの可能性があります（名前は表示しません）'
    i_dl = 'ダウンロードログ'
    dl_hit = '{0} : 悪意あるペイロードのダウンロード記録 ({1})'
    dl_ok = '{0} : 記録なし'
    i_payload = 'ペイロードファイル'
    pl_hash = '{0} : 公開されたペイロードのハッシュと一致'
    pl_size = '{0} : ペイロードと同じサイズ（205,135バイト）。複数のビルドがあり、ハッシュが違っても安全とは限りません'
    i_state = 'エージェント状態'
    st_hit = '{0} のLocal Storageで k2f.agent を検出（内容は表示しません）'
    st_ok = '{0} のLocal Storageに k2f.agent なし（圧縮された .ldb の古い値は見えない場合があります）'
    st_none = '{0} のLocal Storageなし'
    i_loader = 'ローダーの痕跡'
    ld_hit = '{0} のキャッシュでローダーの痕跡を検出。攻撃者サーバーへの接続の痕跡で、エージェント実行は他の項目で判断します'
    ld_ok = '{0} のコードキャッシュにローダーの痕跡なし'
    i_cache = '改ざんファイルのキャッシュ'
    ca_hit = '{0} のHTTPキャッシュに改ざんJSファイルが残っています。次回起動前に tbs_cache の削除が必要です'
    ca_ok = '{0} のHTTPキャッシュに既知の改ざんファイルなし'
    i_dll = 'ブラウザDLL'
    i_baddll = 'ブラウザの悪意あるDLL'
    dll_signed = '{0} : GoogleまたはMicrosoftの有効な署名があるため悪意ありと判定しません。場所のみ手動で確認してください'
    dll_other = '{0} : 同名の署名なしファイル。既知のパスではないため追加確認が必要です'
    i_hexdir = 'ブラウザのハッシュフォルダ'
    hex_only = '{0} : DLLなしで64桁のフォルダのみ残っています。削除の痕跡の可能性があります'
    dll_ok = 'AppDataに該当DLLなし、ブラウザプロファイル{0}個を確認。PlatformExperienceHelperフォルダ自体は正常です。カスタムプロファイルは見つからない場合があります'
    dll_noapp = 'AppDataのパスが見つかりません'
    i_chromeold = 'Chrome旧バージョンのパス'
    old_hit = '{0} が存在します。署名がないため追加確認が必要です'
    i_reg = 'レジストリ'
    reg_hit = '{0} キーが存在します（値が空でも痕跡です）。{1}'
    reg_none = '接続先なし'
    reg_file = '接続ファイルあり: {0}'
    reg_nofile = '接続ファイルなし: {0}'
    reg_other = '{0} が同名のDLLを指しています'
    reg_ok = 'HKCUのCLSIDキーなし、同じDLLを指すCOM登録なし'
    i_other = '他のアカウント'
    other_ok = '読み込み済みアカウント {0} のレジストリを確認（サインアウト中のアカウントは確認不可）'
    i_temp = '一時ファイル'
    tmp_hit = 'TEMPで{0}個検出: {1}'
    tmp_ok = 'k2fの一時ファイルなし（マルウェアが使用後に削除するため安全の保証にはなりません）'
    i_conn = '現在の接続'
    conn_hit = '攻撃者サーバーのIPに接続中: {0}'
    conn_ok = '攻撃者サーバーのIPへの接続なし'
    conn_na = '接続情報を確認できません'
    i_dns = 'DNSキャッシュ'
    dns_hit = '最近の照会記録: {0}。insightjs.org は第三者の警告ページなので、このドメインのみなら危険度は低めです'
    dns_ok = 'insightjsの照会記録なし（再起動で消えます）'
    i_read = 'ファイル読み取り'
    read_err = '{0}個のファイルを読み取れず除外しました'
    step_fail = 'チェック失敗: {0}'
    v_danger = '危険: このPCで悪意あるエージェントが実行された痕跡があります。'
    v_warn = '注意: 実行の記録はありませんが、改ざんファイルまたは攻撃者サーバーへの接続の痕跡があります。'
    v_fail = '判定制限: 一部のチェックを完了できませんでした。下の確認不可の項目をご確認ください。'
    v_nolog = '判定制限: ランチャー使用の痕跡はありますが、debug.log がなく実行記録を確認できません。'
    v_none = '判定制限: このWindowsアカウントでNIKKE PCランチャーの使用痕跡は見つかりません。他のアカウントや削除済みの環境は確認できません。'
    v_ok = '既知の痕跡は見つかりません。安全という意味ではありません。'
    r_title = 'NIKKE PCランチャー 感染痕跡チェック結果'
    r_time = '確認日時: {0}'
    r_dir = 'インストールフォルダ: {0}'
    r_nodir = '見つかりません'
    r_verdict = '判定: {0}'
    r_saved = '結果ファイル: {0}'
    r_savefail = '結果ファイルを保存できません: {0}'
    r_mt = '機械翻訳を含みます。誤訳は GitHub Issues でお知らせください。'
    d_head = 'このツールは何も変更していません。次の対応はご自身で行ってください（報告書の推奨順）。'
    d1 = '1. ランチャーを閉じるかインターネットを切断する'
    d2 = '2. HKCUキーを削除 -> 再起動 -> 64桁のフォルダのみ削除（PlatformExperienceHelperフォルダ全体とHKLMの項目は削除しないこと）'
    d_key = '   レジストリキー: {0}'
    d_dir = '   フォルダ: {0}'
    d_file = '   ファイル: {0}'
    d3 = '3. 最も安全なのはWindowsの再インストール'
    d4 = '4. 別のクリーンな端末で、NIKKE、メールの順にパスワード変更、二段階認証の設定、全セッションからログアウト'
    d5 = '5. APIトークン、SSHキー、開発者認証情報を失効させて再発行'
    d6 = '6. 暗号資産は新しいシードの新しいウォレットへ移動'
    d7 = 'ウイルス検査で問題がなくても除去の保証にはなりません（Defenderオフラインスキャンが検出できなかった報告あり）。'
    n_head = '参考'
    n1 = '- 公開された痕跡のみ確認します。消去された痕跡や削除されたログは見つかりません。'
    n2 = '- 2026年10月23日(GMT)以降にランチャーを起動した場合、主要パスワードの変更とセッションのログアウトを推奨します。'
    n3 = '- 公式の対応を確認するまでランチャーを開かず、再度開く前に %APPDATA%\nikke_launcher\tbs_cache を削除してください。'
  }
  'zh-Hant' = @{
    title = '=== NIKKE PC 啟動器感染痕跡檢查（唯讀） ==='
    intro = '不會刪除或變更任何內容。尋找安裝資料夾可能需要 1～2 分鐘。'
    deep = '正在深入搜尋安裝資料夾，可能需要數分鐘。'
    ask = '找不到 NIKKE 安裝資料夾。請輸入路徑（沒有請直接按 Enter）'
    badpath = '該路徑沒有 Launcher 資料夾，已略過。'
    i_scan = '安裝資料夾搜尋'
    scan_cut = '搜尋已於 {0} 秒上限停止。若有安裝 NIKKE，請使用 -NikkePath 或 -DeepScan。'
    L_danger = '危險'
    L_warn = '注意'
    L_unknown = '無法確認'
    L_ok = '正常'
    i_run = '啟動器執行'
    running = '{0} 正在執行。本工具不會關閉它，請連同系統匣一併自行關閉。'
    notrunning = '沒有 NIKKE 啟動器相關處理程序'
    i_log = '啟動器記錄'
    log_hit = '{0} : 代理程式執行紀錄 ({1})'
    log_start = '{0} : 發現 startup already in progress。沒有代理程式啟動紀錄，僅憑此行無法判斷'
    log_ok = '{0} : 沒有執行紀錄'
    log_none = '找不到 {0}'
    log_noroot = '找不到安裝資料夾，未檢查 debug.log（已刪除或安裝在其他位置）'
    i_pcname = '記錄的電腦名稱'
    pc_same = '記錄中的電腦名稱與此電腦相符（不顯示名稱）'
    pc_diff = '記錄中的電腦名稱與此電腦不同，可能已改名或資料夾複製自其他電腦（不顯示名稱）'
    i_dl = '下載記錄'
    dl_hit = '{0} : 惡意酬載下載紀錄 ({1})'
    dl_ok = '{0} : 沒有紀錄'
    i_payload = '酬載檔案'
    pl_hash = '{0} : 與公開的酬載雜湊相符'
    pl_size = '{0} : 大小與酬載相同（205,135 位元組）。存在多個版本，雜湊不同不代表安全'
    i_state = '代理程式狀態'
    st_hit = '在 {0} 的 Local Storage 發現 k2f.agent（不顯示內容）'
    st_ok = '{0} 的 Local Storage 沒有 k2f.agent（壓縮 .ldb 中的舊值可能無法看到）'
    st_none = '找不到 {0} 的 Local Storage'
    i_loader = '載入器痕跡'
    ld_hit = '在 {0} 快取發現載入器痕跡。這是連線至攻擊者伺服器的痕跡，代理程式是否執行請看其他項目'
    ld_ok = '{0} 的程式碼快取沒有載入器痕跡'
    i_cache = '遭竄改檔案快取'
    ca_hit = '{0} 的 HTTP 快取仍有遭竄改的 JS 檔案。下次啟動前需刪除 tbs_cache'
    ca_ok = '{0} 的 HTTP 快取沒有已知遭竄改檔案'
    i_dll = '瀏覽器 DLL'
    i_baddll = '瀏覽器惡意 DLL'
    dll_signed = '{0} : 具有 Google 或 Microsoft 有效簽章，不判定為惡意。請手動確認位置'
    dll_other = '{0} : 同名的未簽章檔案，不在已知路徑，需進一步確認'
    i_hexdir = '瀏覽器雜湊資料夾'
    hex_only = '{0} : 只留下 64 位資料夾而沒有 DLL，可能是刪除後的痕跡'
    dll_ok = 'AppData 沒有該 DLL，已檢查 {0} 個瀏覽器設定檔。PlatformExperienceHelper 資料夾本身正常。自訂設定檔路徑可能找不到'
    dll_noapp = '找不到 AppData 路徑'
    i_chromeold = 'Chrome 舊版路徑'
    old_hit = '{0} 存在。未簽章，需進一步確認'
    i_reg = '登錄檔'
    reg_hit = '{0} 機碼存在（值為空也屬痕跡）。{1}'
    reg_none = '沒有連結目標'
    reg_file = '連結檔案存在：{0}'
    reg_nofile = '連結檔案不存在：{0}'
    reg_other = '{0} 指向同名 DLL'
    reg_ok = '沒有 HKCU CLSID 機碼，也沒有指向該 DLL 的 COM 登錄'
    i_other = '其他帳戶'
    other_ok = '已檢查已載入帳戶 {0} 的登錄檔（已登出帳戶無法檢查）'
    i_temp = '暫存檔'
    tmp_hit = '在 TEMP 發現 {0} 個：{1}'
    tmp_ok = '沒有 k2f 暫存檔（惡意程式用後即刪，不代表安全）'
    i_conn = '目前連線'
    conn_hit = '正連線至攻擊者伺服器 IP：{0}'
    conn_ok = '沒有連線至攻擊者伺服器 IP'
    conn_na = '無法取得連線資訊'
    i_dns = 'DNS 快取'
    dns_hit = '最近查詢紀錄：{0}。insightjs.org 現為第三方警告頁面，僅有此網域時風險較低'
    dns_ok = '沒有 insightjs 查詢紀錄（重新開機後清除）'
    i_read = '檔案讀取'
    read_err = '有 {0} 個檔案無法讀取，已略過'
    step_fail = '檢查失敗：{0}'
    v_danger = '危險：有痕跡顯示惡意代理程式曾在此電腦執行。'
    v_warn = '注意：沒有執行紀錄，但有遭竄改檔案或連線至攻擊者伺服器的痕跡。'
    v_fail = '判定受限：部分檢查未完成，請查看下方無法確認的項目。'
    v_nolog = '判定受限：有使用啟動器的痕跡，但沒有 debug.log，無法確認執行紀錄。'
    v_none = '判定受限：此 Windows 帳戶未發現使用 NIKKE PC 啟動器的痕跡。其他帳戶或已刪除的安裝無法檢查。'
    v_ok = '未發現已知痕跡。這不代表安全。'
    r_title = 'NIKKE PC 啟動器感染痕跡檢查結果'
    r_time = '檢查時間：{0}'
    r_dir = '安裝資料夾：{0}'
    r_nodir = '找不到'
    r_verdict = '判定：{0}'
    r_saved = '結果檔案：{0}'
    r_savefail = '無法儲存結果檔案：{0}'
    r_mt = '內容包含機器翻譯，翻譯錯誤請透過 GitHub Issues 回報。'
    d_head = '本工具未變更任何內容。請自行採取以下措施（依報告建議順序）。'
    d1 = '1. 關閉啟動器或中斷網路'
    d2 = '2. 刪除 HKCU 機碼 -> 重新開機 -> 只刪除 64 位資料夾（切勿刪除整個 PlatformExperienceHelper 資料夾或 HKLM 項目）'
    d_key = '   登錄機碼：{0}'
    d_dir = '   資料夾：{0}'
    d_file = '   檔案：{0}'
    d3 = '3. 最安全的做法是重新安裝 Windows'
    d4 = '4. 在另一台乾淨裝置上依序變更 NIKKE、電子郵件等密碼，啟用雙重驗證，登出所有工作階段'
    d5 = '5. 撤銷並重新核發 API 權杖、SSH 金鑰與開發者憑證'
    d6 = '6. 將加密資產轉移到使用新助記詞的新錢包'
    d7 = '防毒掃描正常也不保證已清除（有 Defender 離線掃描未偵測到 DLL 的回報）。'
    n_head = '參考'
    n1 = '- 僅檢查已公開的痕跡。已被清除的痕跡或已刪除的記錄無法發現。'
    n2 = '- 若在 2026 年 10 月 23 日 (GMT) 之後執行過啟動器，建議變更主要密碼並登出工作階段。'
    n3 = '- 確認官方處置前請勿開啟啟動器，再次開啟前請刪除 %APPDATA%\nikke_launcher\tbs_cache。'
  }
  'zh-Hans' = @{
    title = '=== NIKKE PC 启动器感染痕迹检查（只读） ==='
    intro = '不会删除或更改任何内容。查找安装文件夹可能需要 1～2 分钟。'
    deep = '正在深入搜索安装文件夹，可能需要数分钟。'
    ask = '找不到 NIKKE 安装文件夹。请输入路径（没有请直接按 Enter）'
    badpath = '该路径没有 Launcher 文件夹，已跳过。'
    i_scan = '安装文件夹搜索'
    scan_cut = '搜索已在 {0} 秒上限停止。若已安装 NIKKE，请使用 -NikkePath 或 -DeepScan。'
    L_danger = '危险'
    L_warn = '注意'
    L_unknown = '无法确认'
    L_ok = '正常'
    i_run = '启动器运行'
    running = '{0} 正在运行。本工具不会关闭它，请连同系统托盘一并自行关闭。'
    notrunning = '没有 NIKKE 启动器相关进程'
    i_log = '启动器日志'
    log_hit = '{0} : 代理程序运行记录 ({1})'
    log_start = '{0} : 发现 startup already in progress。没有代理程序启动记录，仅凭此行无法判断'
    log_ok = '{0} : 没有运行记录'
    log_none = '找不到 {0}'
    log_noroot = '找不到安装文件夹，未检查 debug.log（已删除或安装在其他位置）'
    i_pcname = '记录的电脑名称'
    pc_same = '日志中的电脑名称与此电脑一致（不显示名称）'
    pc_diff = '日志中的电脑名称与此电脑不同，可能已改名或文件夹复制自其他电脑（不显示名称）'
    i_dl = '下载日志'
    dl_hit = '{0} : 恶意载荷下载记录 ({1})'
    dl_ok = '{0} : 没有记录'
    i_payload = '载荷文件'
    pl_hash = '{0} : 与公开的载荷哈希一致'
    pl_size = '{0} : 大小与载荷相同（205,135 字节）。存在多个版本，哈希不同不代表安全'
    i_state = '代理程序状态'
    st_hit = '在 {0} 的 Local Storage 发现 k2f.agent（不显示内容）'
    st_ok = '{0} 的 Local Storage 没有 k2f.agent（压缩 .ldb 中的旧值可能无法看到）'
    st_none = '找不到 {0} 的 Local Storage'
    i_loader = '加载器痕迹'
    ld_hit = '在 {0} 缓存发现加载器痕迹。这是连接攻击者服务器的痕迹，代理程序是否运行请看其他项目'
    ld_ok = '{0} 的代码缓存没有加载器痕迹'
    i_cache = '被篡改文件缓存'
    ca_hit = '{0} 的 HTTP 缓存仍有被篡改的 JS 文件。下次启动前需删除 tbs_cache'
    ca_ok = '{0} 的 HTTP 缓存没有已知被篡改文件'
    i_dll = '浏览器 DLL'
    i_baddll = '浏览器恶意 DLL'
    dll_signed = '{0} : 具有 Google 或 Microsoft 有效签名，不判定为恶意。请手动确认位置'
    dll_other = '{0} : 同名的未签名文件，不在已知路径，需进一步确认'
    i_hexdir = '浏览器哈希文件夹'
    hex_only = '{0} : 只留下 64 位文件夹而没有 DLL，可能是删除后的痕迹'
    dll_ok = 'AppData 没有该 DLL，已检查 {0} 个浏览器配置文件。PlatformExperienceHelper 文件夹本身正常。自定义配置路径可能找不到'
    dll_noapp = '找不到 AppData 路径'
    i_chromeold = 'Chrome 旧版路径'
    old_hit = '{0} 存在。未签名，需进一步确认'
    i_reg = '注册表'
    reg_hit = '{0} 键存在（值为空也属痕迹）。{1}'
    reg_none = '没有链接目标'
    reg_file = '链接文件存在：{0}'
    reg_nofile = '链接文件不存在：{0}'
    reg_other = '{0} 指向同名 DLL'
    reg_ok = '没有 HKCU CLSID 键，也没有指向该 DLL 的 COM 注册'
    i_other = '其他账户'
    other_ok = '已检查已加载账户 {0} 的注册表（已退出账户无法检查）'
    i_temp = '临时文件'
    tmp_hit = '在 TEMP 发现 {0} 个：{1}'
    tmp_ok = '没有 k2f 临时文件（恶意程序用后即删，不代表安全）'
    i_conn = '当前连接'
    conn_hit = '正连接攻击者服务器 IP：{0}'
    conn_ok = '没有连接攻击者服务器 IP'
    conn_na = '无法获取连接信息'
    i_dns = 'DNS 缓存'
    dns_hit = '最近查询记录：{0}。insightjs.org 现为第三方警告页面，仅有此域名时风险较低'
    dns_ok = '没有 insightjs 查询记录（重启后清除）'
    i_read = '文件读取'
    read_err = '有 {0} 个文件无法读取，已跳过'
    step_fail = '检查失败：{0}'
    v_danger = '危险：有痕迹显示恶意代理程序曾在此电脑运行。'
    v_warn = '注意：没有运行记录，但有被篡改文件或连接攻击者服务器的痕迹。'
    v_fail = '判定受限：部分检查未完成，请查看下方无法确认的项目。'
    v_nolog = '判定受限：有使用启动器的痕迹，但没有 debug.log，无法确认运行记录。'
    v_none = '判定受限：此 Windows 账户未发现使用 NIKKE PC 启动器的痕迹。其他账户或已删除的安装无法检查。'
    v_ok = '未发现已知痕迹。这不代表安全。'
    r_title = 'NIKKE PC 启动器感染痕迹检查结果'
    r_time = '检查时间：{0}'
    r_dir = '安装文件夹：{0}'
    r_nodir = '找不到'
    r_verdict = '判定：{0}'
    r_saved = '结果文件：{0}'
    r_savefail = '无法保存结果文件：{0}'
    r_mt = '内容包含机器翻译，翻译错误请通过 GitHub Issues 反馈。'
    d_head = '本工具未更改任何内容。请自行采取以下措施（按报告建议顺序）。'
    d1 = '1. 关闭启动器或断开网络'
    d2 = '2. 删除 HKCU 键 -> 重启 -> 只删除 64 位文件夹（切勿删除整个 PlatformExperienceHelper 文件夹或 HKLM 项）'
    d_key = '   注册表键：{0}'
    d_dir = '   文件夹：{0}'
    d_file = '   文件：{0}'
    d3 = '3. 最安全的做法是重装 Windows'
    d4 = '4. 在另一台干净设备上依次更改 NIKKE、邮箱等密码，启用双重验证，退出所有会话'
    d5 = '5. 吊销并重新签发 API 令牌、SSH 密钥和开发者凭据'
    d6 = '6. 将加密资产转移到使用新助记词的新钱包'
    d7 = '杀毒扫描正常也不保证已清除（有 Defender 离线扫描未检测到 DLL 的报告）。'
    n_head = '参考'
    n1 = '- 仅检查已公开的痕迹。已被清除的痕迹或已删除的日志无法发现。'
    n2 = '- 若在 2026 年 10 月 23 日 (GMT) 之后运行过启动器，建议更改主要密码并退出会话。'
    n3 = '- 确认官方处置前请勿打开启动器，再次打开前请删除 %APPDATA%\nikke_launcher\tbs_cache。'
  }
}

if (-not $Language) {
    $ui = ''
    try { $ui = (Get-UICulture).Name } catch { }
    if ($ui -match '^ko') { $Language = 'ko' }
    elseif ($ui -match '^ja') { $Language = 'ja' }
    elseif ($ui -match '^zh-(TW|HK|MO|Hant)') { $Language = 'zh-Hant' }
    elseif ($ui -match '^zh') { $Language = 'zh-Hans' }
    else { $Language = 'en' }
}
function T {
    param([string]$Key, [Parameter(ValueFromRemainingArguments = $true)][object[]]$A)
    $s = $script:Strings[$Language][$Key]
    if ($A -and $A.Count -gt 0) { return ($s -f $A) }
    return $s
}

$script:Findings = New-Object System.Collections.ArrayList
$script:Latin1 = [Text.Encoding]::GetEncoding(28591)
$script:MaxBytes = 1GB
$script:ReadErrors = 0
$script:StepFailed = 0
$script:ManualRegKeys = New-Object System.Collections.ArrayList
$script:ManualFolders = New-Object System.Collections.ArrayList
$script:ManualFiles = New-Object System.Collections.ArrayList
$script:KnownPayloadHash = 'cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec'
$script:DllName = 'platform_experience_helper.dll'

function P {
    param([string]$Base, [Parameter(ValueFromRemainingArguments = $true)][string[]]$Parts)
    $r = $Base
    foreach ($x in $Parts) { $r = [IO.Path]::Combine($r, $x) }
    return $r
}
function Add-Finding {
    param([string]$Level, [string]$Item, [string]$Detail)
    [void]$script:Findings.Add([PSCustomObject]@{ Level = $Level; Item = $Item; Detail = $Detail })
}
function Read-Shared {
    param([string]$Path)
    $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try {
        $len = [int]$fs.Length
        $buf = New-Object byte[] $len
        $off = 0
        while ($off -lt $len) {
            $n = $fs.Read($buf, $off, $len - $off)
            if ($n -le 0) { break }
            $off += $n
        }
        return $script:Latin1.GetString($buf, 0, $off)
    } finally { $fs.Dispose() }
}
# Counts only. Matched content is never printed (PC names, agent_pass).
function Search-Files {
    param([System.IO.FileInfo[]]$Files, [string[]]$Needles)
    $counts = @{}
    foreach ($n in $Needles) { $counts[$n] = 0 }
    $hitFiles = @{}
    foreach ($f in $Files) {
        if ($f.Length -gt $script:MaxBytes) { $script:ReadErrors++; continue }
        try { $text = Read-Shared $f.FullName } catch { $script:ReadErrors++; continue }
        foreach ($n in $Needles) {
            $c = [regex]::Matches($text, [regex]::Escape($n)).Count
            if ($c -gt 0) { $counts[$n] += $c; $hitFiles[$f.FullName] = $true }
        }
    }
    return [PSCustomObject]@{ Counts = $counts; HitFiles = @($hitFiles.Keys) }
}
function Get-FilesSafe {
    param([string]$Dir, [string]$Filter = '*', [switch]$Recurse)
    if (-not (Test-Path -LiteralPath $Dir)) { return @() }
    $a = @{ LiteralPath = $Dir; File = $true; Force = $true; ErrorAction = 'SilentlyContinue' }
    if ($Recurse) { $a.Recurse = $true }
    return @(Get-ChildItem @a | Where-Object { $_.Name -like $Filter })
}
function Format-Counts {
    param($Counts)
    return (($Counts.GetEnumerator() | Where-Object { $_.Value -gt 0 } |
        ForEach-Object { "'$($_.Key)' x$($_.Value)" }) -join ', ')
}
function Invoke-Step {
    param([string]$Name, [scriptblock]$Body)
    try { & $Body }
    catch {
        $script:StepFailed++
        Add-Finding 'unknown' $Name (T 'step_fail' $_.Exception.Message)
    }
}
function Get-RegDefault {
    param([string]$KeyPath)
    try { return (Get-Item -LiteralPath $KeyPath -ErrorAction Stop).GetValue('') } catch { return $null }
}
function Resolve-RegPath {
    param([string]$Value)
    if (-not $Value) { return '' }
    $v = [Environment]::ExpandEnvironmentVariables($Value).Trim()
    if ($v -match '^"([^"]+)"') { return $Matches[1] }
    return ($v -replace ',\s*-?\d+$', '')
}

# ---------- 1. Install folders (official, Google Play Games, custom paths) ----------
function Find-NikkeRoots {
    $found = New-Object System.Collections.ArrayList
    foreach ($p in $NikkePath) { [void]$found.Add($p) }
    if ($env:LOCALAPPDATA) { [void]$found.Add((P $env:LOCALAPPDATA 'NIKKE')) }
    foreach ($u in @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
        Get-ItemProperty -Path $u -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -match 'NIKKE' -and $_.InstallLocation } |
            ForEach-Object { [void]$found.Add($_.InstallLocation) }
    }
    if ($env:NIKKE_LAUNCHER) { [void]$found.Add($env:NIKKE_LAUNCHER) }
    foreach ($hive in @('HKCU:', 'HKLM:')) {
        $exe = Resolve-RegPath (Get-RegDefault "$hive\Software\Microsoft\Windows\CurrentVersion\App Paths\nikke_launcher.exe")
        if ($exe) {
            $d = Split-Path -Parent $exe
            for ($i = 0; $i -lt 4 -and $d; $i++) { [void]$found.Add($d); $d = Split-Path -Parent $d }
        }
    }
    $roots = @{}
    $addRoot = {
        param($c)
        if (-not $c) { return }
        $full = $null
        if (Test-Path -LiteralPath (P $c 'Launcher')) { $full = P $c 'Launcher' }
        elseif (Test-Path -LiteralPath (P $c 'intl_service')) { $full = $c }
        if ($full) { $roots[(Resolve-Path -LiteralPath $full).Path] = $true }
    }
    foreach ($c in $found) { & $addRoot $c }
    # Time-limited breadth-first search of local fixed disks. Network, removable and very slow drives cannot hang the check.
    $starts = @($SearchRoot)
    if ($starts.Count -eq 0) {
        $starts = @([IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq [IO.DriveType]::Fixed -and $_.IsReady -and $_.Name -match '^[A-Za-z]:\\$' } | ForEach-Object { $_.Name })
    }
    $maxDepth = 4; $limit = 60
    if ($DeepScan) { $maxDepth = 9; $limit = 1800; Write-Host (T 'deep') }
    if ($ScanSeconds -gt 0) { $limit = $ScanSeconds }
    $skip = '^(Windows|\$Recycle\.Bin|System Volume Information|Recovery|PerfLogs)$'
    $queue = New-Object System.Collections.Queue
    foreach ($st in $starts) { $queue.Enqueue(@($st, 0)) }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($queue.Count -gt 0) {
        if ($sw.Elapsed.TotalSeconds -ge $limit) { $script:ScanCut = $limit; break }
        $cur = $queue.Dequeue()
        $kids = @(Get-ChildItem -LiteralPath $cur[0] -Directory -Force -ErrorAction SilentlyContinue)
        foreach ($k in $kids) {
            if ($cur[1] -eq 0 -and $k.Name -match $skip) { continue }
            if ($k.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
            if ($k.Name -match 'NIKKE') { & $addRoot $k.FullName }
            elseif ($k.Name -eq 'intl_service') { & $addRoot (Split-Path -Parent $k.FullName) }
            if (($cur[1] + 1) -lt $maxDepth) { $queue.Enqueue(@($k.FullName, ($cur[1] + 1))) }
        }
    }
    return @($roots.Keys)
}

Write-Host ''
Write-Host (T 'title') -ForegroundColor Cyan
Write-Host (T 'intro')
Write-Host ''

$script:ScanCut = 0
$roots = @(Find-NikkeRoots)
if ($roots.Count -eq 0 -and -not $NoPrompt) {
    $ans = Read-Host (T 'ask')
    if ($ans) {
        $ans = $ans.Trim('"', ' ')
        if (Test-Path -LiteralPath (P $ans 'Launcher')) { $roots = @((P $ans 'Launcher')) }
        elseif (Test-Path -LiteralPath (P $ans 'intl_service')) { $roots = @($ans) }
        else { Write-Host (T 'badpath') -ForegroundColor Yellow }
    }
}

# ---------- 2. Launcher running ----------
if ($script:ScanCut -gt 0) { Add-Finding 'unknown' (T 'i_scan') (T 'scan_cut' $script:ScanCut) }
$running = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match 'nikke|tbs_browser' })
if ($running.Count -gt 0) {
    Add-Finding 'warn' (T 'i_run') (T 'running' (($running | Select-Object -ExpandProperty ProcessName -Unique) -join ', '))
} else {
    Add-Finding 'ok' (T 'i_run') (T 'notrunning')
}

# ---------- 3. Install folder logs ----------
$strongLog = @('k2f_chan', 'agent started as', 'lua downloaded to log')
$logChecked = $false
$bundleEtags = @('6ae78037-3214f', '6ae8ccff-3214f', '6ae90538-3214f', '6ae9d408-3214f', '6ae9f628-3214f')
foreach ($r in $roots) {
    $log = P $r 'intl_service' 'debug.log'
    $logs = @(Get-FilesSafe (P $r 'intl_service') 'debug*.log')
    if ($logs.Count -gt 0) {
        $logChecked = $true
        $res = Search-Files $logs ($strongLog + 'startup already in progress')
        $strong = 0
        foreach ($s in $strongLog) { $strong += $res.Counts[$s] }
        if ($strong -gt 0) {
            Add-Finding 'danger' (T 'i_log') (T 'log_hit' $log (Format-Counts $res.Counts))
            foreach ($lf in $logs) {
                try { $t = Read-Shared $lf.FullName } catch { continue }
                $names = @([regex]::Matches($t, 'agent started as ([^"\r\n]+)') | ForEach-Object { $_.Groups[1].Value.Trim() } | Select-Object -Unique)
                if ($names.Count -gt 0) {
                    if ($names -contains $env:COMPUTERNAME) { Add-Finding 'danger' (T 'i_pcname') (T 'pc_same') }
                    else { Add-Finding 'warn' (T 'i_pcname') (T 'pc_diff') }
                }
            }
        } elseif ($res.Counts['startup already in progress'] -gt 0) {
            Add-Finding 'warn' (T 'i_log') (T 'log_start' $log)
        } else {
            Add-Finding 'ok' (T 'i_log') (T 'log_ok' $log)
        }
    } else {
        Add-Finding 'unknown' (T 'i_log') (T 'log_none' $log)
    }
    foreach ($tiny in @((P $r 'log' 'tinyget'), (P $r 'intl_service' 'log' 'tinyget'))) {
        $tinyFiles = @(Get-FilesSafe $tiny)
        if ($tinyFiles.Count -eq 0) { continue }
        $res = Search-Files $tinyFiles (@('insight.bundle', 'insightjs.com') + $bundleEtags)
        if ($res.HitFiles.Count -gt 0) {
            Add-Finding 'danger' (T 'i_dl') (T 'dl_hit' $tiny (Format-Counts $res.Counts))
        } else {
            Add-Finding 'ok' (T 'i_dl') (T 'dl_ok' $tiny)
        }
        foreach ($tf in $tinyFiles) {
            if ($tf.Name -eq 'k2f.lua') {
                Add-Finding 'danger' (T 'i_payload') $tf.FullName
                [void]$script:ManualFiles.Add($tf.FullName)
            } elseif ($tf.Length -eq 205135) {
                $h = ''
                try { $h = (Get-FileHash -LiteralPath $tf.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() } catch { }
                if ($h -eq $script:KnownPayloadHash) { Add-Finding 'danger' (T 'i_payload') (T 'pl_hash' $tf.FullName) }
                else { Add-Finding 'danger' (T 'i_payload') (T 'pl_size' $tf.FullName) }
                [void]$script:ManualFiles.Add($tf.FullName)
            }
        }
    }
}
if ($roots.Count -eq 0) { Add-Finding 'unknown' (T 'i_log') (T 'log_noroot') }

# ---------- 4. Launcher data in AppData (survives deleting the NIKKE folder) ----------
$launcherDataFound = $false
$dataDirs = @()
if ($env:APPDATA -and (Test-Path -LiteralPath $env:APPDATA)) {
    $dataDirs = @(Get-ChildItem -LiteralPath $env:APPDATA -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'nikke*launcher*' })
}
$loaderCacheNames = @('dd65fa4d61079e7e_0', 'ce2fd3f1007a9fe9_0', '1416c638b3830103_0', 'fd520c7c0f65c2d7_0')
foreach ($dir in $dataDirs) {
    $launcherDataFound = $true
    $name = $dir.Name
    $tbs = P $dir.FullName 'tbs_cache'
    $lsFiles = @(Get-FilesSafe (P $tbs 'Local Storage' 'leveldb'))
    if ($lsFiles.Count -gt 0) {
        $res = Search-Files $lsFiles @('k2f.agent')
        if ($res.HitFiles.Count -gt 0) { Add-Finding 'danger' (T 'i_state') (T 'st_hit' $name) }
        else { Add-Finding 'ok' (T 'i_state') (T 'st_ok' $name) }
    } else {
        Add-Finding 'unknown' (T 'i_state') (T 'st_none' $name)
    }
    $codeFiles = @(Get-FilesSafe (P $tbs 'Code Cache' 'js') -Recurse)
    $persist = @(Get-FilesSafe $tbs 'Network Persistent State' -Recurse)
    $res = Search-Files ($codeFiles + $persist) @('insightjs.com')
    $namedHit = @($codeFiles | Where-Object { $loaderCacheNames -contains $_.Name })
    if ($res.HitFiles.Count -gt 0 -or $namedHit.Count -gt 0) {
        Add-Finding 'warn' (T 'i_loader') (T 'ld_hit' $name)
    } elseif (($codeFiles.Count + $persist.Count) -gt 0) {
        Add-Finding 'ok' (T 'i_loader') (T 'ld_ok' $name)
    }
    $httpFiles = @(Get-FilesSafe (P $tbs 'Cache') -Recurse)
    if ($httpFiles.Count -gt 0) {
        $res = Search-Files $httpFiles @(
            '50d1861152ea7f6875ffceb7d08445b5', '481e9b5ab8fb93406bf31980b53e0578',
            'b7d842200372ad0d9a84ef4cc8511311', 'dd06875637a29cddd3bae2ba84142c78')
        if ($res.HitFiles.Count -gt 0) { Add-Finding 'warn' (T 'i_cache') (T 'ca_hit' $name) }
        else { Add-Finding 'ok' (T 'i_cache') (T 'ca_ok' $name) }
    }
}

# ---------- 5. Browser persistence DLL ----------
# The PlatformExperienceHelper folder itself is normal Chrome; the DLL can be installed without Chrome.
# Each DLL has its own hash, so judge by path and key, not hash.
$script:DllPaths = @{}
function Test-TrustedSignature {
    param([string]$Path)
    if (-not (Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue)) { return $false }
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        return ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match 'Google|Microsoft')
    } catch { return $false }
}
function Register-Dll {
    param([string]$Path)
    $key = $Path.ToLowerInvariant()
    if ($script:DllPaths.ContainsKey($key)) { return }
    $script:DllPaths[$key] = $true
    $parent = Split-Path -Leaf (Split-Path -Parent $Path)
    $grand = Split-Path -Leaf (Split-Path -Parent (Split-Path -Parent $Path))
    if (Test-TrustedSignature $Path) {
        Add-Finding 'warn' (T 'i_dll') (T 'dll_signed' $Path)
    } elseif ($parent -match '^[0-9a-fA-F]{64}$' -and $grand -eq 'PlatformExperienceHelper') {
        Add-Finding 'danger' (T 'i_baddll') $Path
        [void]$script:ManualFolders.Add((Split-Path -Parent $Path))
    } else {
        Add-Finding 'warn' (T 'i_dll') (T 'dll_other' $Path)
    }
}
Invoke-Step (T 'i_dll') {
    $searchRoots = @(@($env:LOCALAPPDATA, $env:APPDATA) | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
    if ($searchRoots.Count -eq 0) { Add-Finding 'unknown' (T 'i_dll') (T 'dll_noapp') }
    foreach ($root in $searchRoots) {
        Get-ChildItem -LiteralPath $root -Recurse -Depth 7 -File -Force -Filter $script:DllName -ErrorAction SilentlyContinue |
            ForEach-Object { Register-Dll $_.FullName }
    }
    $rel = @(
        @('Google','Chrome','User Data'), @('Google','Chrome SxS','User Data'), @('Google','Chrome Beta','User Data'), @('Google','Chrome Dev','User Data'),
        @('Chromium','User Data'), @('Microsoft','Edge','User Data'), @('Microsoft','Edge Beta','User Data'), @('Microsoft','Edge Dev','User Data'),
        @('Microsoft','Edge SxS','User Data'), @('BraveSoftware','Brave-Browser','User Data'), @('BraveSoftware','Brave-Browser-Beta','User Data'),
        @('BraveSoftware','Brave-Browser-Nightly','User Data'), @('Vivaldi','User Data'), @('Yandex','YandexBrowser','User Data'),
        @('Thorium','User Data'), @('CocCoc','Browser','User Data'))
    $browserRoots = New-Object System.Collections.ArrayList
    foreach ($x in $rel) { $b = $env:LOCALAPPDATA; foreach ($y in $x) { $b = P $b $y }; [void]$browserRoots.Add($b) }
    [void]$browserRoots.Add((P $env:APPDATA 'Opera Software' 'Opera Stable'))
    [void]$browserRoots.Add((P $env:APPDATA 'Opera Software' 'Opera GX Stable'))
    $present = @($browserRoots | Where-Object { Test-Path -LiteralPath $_ })
    foreach ($b in $browserRoots) {
        $peh = P $b 'PlatformExperienceHelper'
        if (-not (Test-Path -LiteralPath $peh)) { continue }
        Get-ChildItem -LiteralPath $peh -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^[0-9a-fA-F]{64}$' -and -not (Test-Path -LiteralPath (P $_.FullName $script:DllName)) } |
            ForEach-Object { Add-Finding 'warn' (T 'i_hexdir') (T 'hex_only' $_.FullName) }
    }
    if ($script:DllPaths.Count -eq 0) { Add-Finding 'ok' (T 'i_dll') (T 'dll_ok' $present.Count) }
}
$appDirs = @(
    (P $env:LOCALAPPDATA 'Google' 'Chrome' 'Application'),
    $(if ($env:ProgramFiles) { P $env:ProgramFiles 'Google' 'Chrome' 'Application' }),
    $(if (${env:ProgramFiles(x86)}) { P ${env:ProgramFiles(x86)} 'Google' 'Chrome' 'Application' })
) | Where-Object { $_ }
foreach ($a in $appDirs) {
    foreach ($f in @('service_util.dll', 'platform_experience_helper.dll', 'platform_experience_helper.dll.old', 'old-clsid.txt')) {
        $x = P $a 'PlatformExperienceHelper' $f
        if ((Test-Path -LiteralPath $x) -and -not (Test-TrustedSignature $x)) { Add-Finding 'warn' (T 'i_chromeold') (T 'old_hit' $x) }
    }
}

# ---------- 6. Registry (only the HKCU copy is malicious; the same CLSID in HKLM is normal Windows) ----------
$clsidId = '{E77CC89B-7401-4C04-8CED-149DB35ADD04}'
function Test-UserHive {
    param([string]$HiveRoot, [string]$Label)
    $hit = $false
    foreach ($sub in @('Software\Classes\CLSID', 'Software\Classes\Wow6432Node\CLSID')) {
        $key = "$HiveRoot\$sub\$clsidId"
        if (Test-Path -LiteralPath $key) {
            $hit = $true
            $target = Resolve-RegPath (Get-RegDefault "$key\InprocServer32")
            $state = T 'reg_none'
            if ($target) { if (Test-Path -LiteralPath $target) { $state = T 'reg_file' $target } else { $state = T 'reg_nofile' $target } }
            Add-Finding 'danger' (T 'i_reg') (T 'reg_hit' "$Label\$sub\$clsidId" $state)
            [void]$script:ManualRegKeys.Add("$Label\$sub\$clsidId")
            if ($target -and (Test-Path -LiteralPath $target)) { Register-Dll $target }
        }
        $base = "$HiveRoot\$sub"
        if (Test-Path -LiteralPath $base) {
            Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.PSChildName -ieq $clsidId) { return }
                foreach ($srv in @('InprocServer32', 'LocalServer32')) {
                    $val = Get-RegDefault "$($_.PSPath)\$srv"
                    if ($val -and $val -match 'platform_experience_helper\.dll') {
                        $hit = $true
                        Add-Finding 'danger' (T 'i_reg') (T 'reg_other' "$Label\$sub\$($_.PSChildName)\$srv")
                        [void]$script:ManualRegKeys.Add("$Label\$sub\$($_.PSChildName)")
                    }
                }
            }
        }
    }
    return $hit
}
Invoke-Step (T 'i_reg') {
    if (-not (Test-UserHive 'HKCU:' 'HKCU')) { Add-Finding 'ok' (T 'i_reg') (T 'reg_ok') }
    if ($AllUsers -and (Test-Path 'Registry::HKEY_USERS')) {
        $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' -and $_.PSChildName -ne $me } |
            ForEach-Object {
                $sid = $_.PSChildName
                $null = Test-UserHive "Registry::HKEY_USERS\$sid" "HKU\$sid"
                Add-Finding 'ok' (T 'i_other') (T 'other_ok' $sid)
            }
    }
}

# ---------- 7. Temp files ----------
$tempHits = @(Get-ChildItem -LiteralPath $env:TEMP -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like 'k2f-bcreds-*' -or $_.Name -like 'k2f_screen_*' })
if ($tempHits.Count -gt 0) {
    Add-Finding 'danger' (T 'i_temp') (T 'tmp_hit' $tempHits.Count (($tempHits | Select-Object -First 5 -ExpandProperty Name) -join ', '))
} else {
    Add-Finding 'ok' (T 'i_temp') (T 'tmp_ok')
}

# ---------- 8. Network ----------
$c2 = @('89.127.233.127', '89.126.250.172')
if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
    $conn = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $c2 -contains $_.RemoteAddress })
    if ($conn.Count -gt 0) { Add-Finding 'danger' (T 'i_conn') (T 'conn_hit' (($conn.RemoteAddress | Select-Object -Unique) -join ', ')) }
    else { Add-Finding 'ok' (T 'i_conn') (T 'conn_ok') }
} else {
    Add-Finding 'unknown' (T 'i_conn') (T 'conn_na')
}
if (Get-Command Get-DnsClientCache -ErrorAction SilentlyContinue) {
    $dns = @(Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Entry -match 'insightjs\.(com|org)$' })
    if ($dns.Count -gt 0) { Add-Finding 'warn' (T 'i_dns') (T 'dns_hit' (($dns.Entry | Select-Object -Unique) -join ', ')) }
    else { Add-Finding 'ok' (T 'i_dns') (T 'dns_ok') }
}

# ---------- Result ----------
if ($script:ReadErrors -gt 0) {
    Add-Finding 'unknown' (T 'i_read') (T 'read_err' $script:ReadErrors)
    $script:StepFailed++
}
$danger = @($script:Findings | Where-Object { $_.Level -eq 'danger' })
$warn = @($script:Findings | Where-Object { $_.Level -eq 'warn' })
if ($danger.Count -gt 0) { $verdict = T 'v_danger'; $color = 'Red'; $code = 2 }
elseif ($warn.Count -gt 0) { $verdict = T 'v_warn'; $color = 'Yellow'; $code = 1 }
elseif ($script:StepFailed -gt 0) { $verdict = T 'v_fail'; $color = 'Yellow'; $code = 3 }
elseif ((-not $logChecked) -and $launcherDataFound) { $verdict = T 'v_nolog'; $color = 'Yellow'; $code = 3 }
elseif (-not $logChecked) { $verdict = T 'v_none'; $color = 'Yellow'; $code = 3 }
else { $verdict = T 'v_ok'; $color = 'Green'; $code = 0 }

$lines = New-Object System.Collections.ArrayList
$rows = New-Object System.Collections.ArrayList
[void]$lines.Add((T 'r_title'))
[void]$lines.Add((T 'r_time' (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')))
$dirText = T 'r_nodir'
if ($roots.Count) { $dirText = $roots -join '; ' }
[void]$lines.Add((T 'r_dir' $dirText))
if ($Language -ne 'ko') { [void]$lines.Add((T 'r_mt')) }
[void]$lines.Add('')
[void]$lines.Add((T 'r_verdict' $verdict))
[void]$lines.Add('')
$colors = @{ danger = 'Red'; warn = 'Yellow'; unknown = 'Gray'; ok = 'Green' }
foreach ($lv in @('danger', 'warn', 'unknown', 'ok')) {
    foreach ($f in @($script:Findings | Where-Object { $_.Level -eq $lv })) {
        $text = "[$(T "L_$lv")] $($f.Item): $($f.Detail)"
        [void]$lines.Add($text)
        [void]$rows.Add([PSCustomObject]@{ Text = $text; Color = $colors[$lv] })
    }
}
$tail = New-Object System.Collections.ArrayList
if ($code -eq 2) {
    [void]$tail.Add((T 'd_head')); [void]$tail.Add((T 'd1')); [void]$tail.Add((T 'd2'))
    foreach ($k in $script:ManualRegKeys) { [void]$tail.Add((T 'd_key' $k)) }
    foreach ($k in $script:ManualFolders) { [void]$tail.Add((T 'd_dir' $k)) }
    foreach ($k in $script:ManualFiles) { [void]$tail.Add((T 'd_file' $k)) }
    foreach ($k in @('d3', 'd4', 'd5', 'd6', 'd7')) { [void]$tail.Add((T $k)) }
} else {
    foreach ($k in @('n_head', 'n1', 'n2', 'n3')) { [void]$tail.Add((T $k)) }
}
[void]$lines.Add('')
foreach ($l in $tail) { [void]$lines.Add($l) }

Write-Host ''
Write-Host (T 'r_verdict' $verdict) -ForegroundColor $color
Write-Host ''
foreach ($r in $rows) { Write-Host $r.Text -ForegroundColor $r.Color }
Write-Host ''
foreach ($l in $tail) { Write-Host $l }

if (-not $ReportDir) { $ReportDir = [Environment]::GetFolderPath('Desktop') }
if (-not $ReportDir -or -not (Test-Path -LiteralPath $ReportDir)) { $ReportDir = $env:TEMP }
$out = P $ReportDir ("NIKKE_check_{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
try {
    [IO.File]::WriteAllLines($out, [string[]]$lines, (New-Object Text.UTF8Encoding($true)))
    Write-Host ''
    Write-Host (T 'r_saved' $out) -ForegroundColor Cyan
} catch {
    Write-Host (T 'r_savefail' $_.Exception.Message) -ForegroundColor Yellow
}
exit $code
