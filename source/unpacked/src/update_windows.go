//go:build windows
package main
import("context";"crypto/sha256";"encoding/hex";"encoding/json";"errors";"fmt";"io";"net/http";"os";"os/exec";"path/filepath";"strings";"time")
const stableReleaseAPI="https://api.github.com/repos/Ssensseii/Private-VPN-Next-Public/releases/latest"
type releaseAsset struct{Name string `json:"name"`;URL string `json:"browser_download_url"`}
type stableRelease struct{TagName string `json:"tag_name"`;HTMLURL string `json:"html_url"`;Assets []releaseAsset `json:"assets"`}
type updateInfo struct{CurrentVersion string `json:"currentVersion"`;LatestVersion string `json:"latestVersion"`;Available bool `json:"available"`;ReleaseURL string `json:"releaseUrl"`;Downloaded bool `json:"downloaded"`;RollbackAvailable bool `json:"rollbackAvailable"`;Message string `json:"message"`}
type rollbackState struct{InstallDir string `json:"installDir"`;CreatedAt time.Time `json:"createdAt"`;FromVersion string `json:"fromVersion"`}
var updateHTTPClient=&http.Client{Timeout:90*time.Second}
func latestStableRelease(ctx context.Context)(stableRelease,error){req,e:=http.NewRequestWithContext(ctx,http.MethodGet,stableReleaseAPI,nil);if e!=nil{return stableRelease{},e};req.Header.Set("Accept","application/vnd.github+json");req.Header.Set("X-GitHub-Api-Version","2022-11-28");resp,e:=updateHTTPClient.Do(req);if e!=nil{return stableRelease{},e};defer resp.Body.Close();if resp.StatusCode!=200{return stableRelease{},fmt.Errorf("GitHub API HTTP %d",resp.StatusCode)};var rel stableRelease;e=json.NewDecoder(io.LimitReader(resp.Body,2<<20)).Decode(&rel);if e==nil&&rel.TagName==""{e=errors.New("GitHub не вернул тег релиза")};return rel,e}
func checkStableUpdate(ctx context.Context,current string)(updateInfo,error){i:=updateInfo{CurrentVersion:current,RollbackAvailable:hasRollback()};r,e:=latestStableRelease(ctx);if e!=nil{return i,e};i.LatestVersion=strings.TrimPrefix(r.TagName,"v");i.ReleaseURL=r.HTMLURL;i.Available=compareSemver(i.LatestVersion,current)>0;if i.Available{i.Message="Доступна новая стабильная версия"}else{i.Message="Установлена последняя стабильная версия"};return i,nil}
func downloadVerifiedInstaller(ctx context.Context,r stableRelease,progress func(int64,int64))(string,error){
 var u,s string
 for _,a:=range r.Assets{if a.Name=="PrivateVPN-Next-Setup.exe"{u=a.URL};if a.Name=="SHA256SUMS.txt"{s=a.URL}}
 if u==""||s==""{return "",errors.New("в релизе отсутствует установщик или SHA256SUMS.txt")}
 sumFile,e:=fetchReleaseAsset(ctx,s,64<<10);if e!=nil{return "",e}
 expected,e:=checksumFor(string(sumFile),"PrivateVPN-Next-Setup.exe");if e!=nil{return "",e}
 req,e:=http.NewRequestWithContext(ctx,http.MethodGet,u,nil);if e!=nil{return "",e};req.Header.Set("Accept","application/octet-stream")
 resp,e:=updateHTTPClient.Do(req);if e!=nil{return "",e};defer resp.Body.Close()
 if resp.StatusCode!=http.StatusOK{return "",fmt.Errorf("загрузка вернула HTTP %d",resp.StatusCode)}
 if resp.ContentLength>1<<30{return "",errors.New("файл превышает допустимый размер")}
 d:=filepath.Join(appDataDir(),"updates");if e=os.MkdirAll(d,0700);e!=nil{return "",e}
 p:=filepath.Join(d,"PrivateVPN-Next-Setup.exe");tmp:=p+".download";f,e:=os.OpenFile(tmp,os.O_CREATE|os.O_TRUNC|os.O_WRONLY,0700);if e!=nil{return "",e}
 h:=sha256.New();buf:=make([]byte,128<<10);var done int64
 for {n,readErr:=resp.Body.Read(buf);if n>0{if _,e=f.Write(buf[:n]);e!=nil{f.Close();os.Remove(tmp);return "",e};h.Write(buf[:n]);done+=int64(n);if progress!=nil{progress(done,resp.ContentLength)};if done>1<<30{f.Close();os.Remove(tmp);return "",errors.New("файл превышает допустимый размер")}};if readErr==io.EOF{break};if readErr!=nil{f.Close();os.Remove(tmp);return "",readErr}}
 if e=f.Close();e!=nil{os.Remove(tmp);return "",e}
 if resp.ContentLength>0&&done!=resp.ContentLength{os.Remove(tmp);return "",errors.New("загрузка установщика завершилась не полностью")}
 if !strings.EqualFold(hex.EncodeToString(h.Sum(nil)),expected){os.Remove(tmp);return "",errors.New("SHA-256 установщика не совпадает")}
 if e=os.Rename(tmp,p);e!=nil{os.Remove(tmp);return "",e};return p,nil
}
func fetchReleaseAsset(ctx context.Context,u string,max int64)([]byte,error){q,e:=http.NewRequestWithContext(ctx,http.MethodGet,u,nil);if e!=nil{return nil,e};q.Header.Set("Accept","application/octet-stream");r,e:=updateHTTPClient.Do(q);if e!=nil{return nil,e};defer r.Body.Close();if r.StatusCode!=200{return nil,fmt.Errorf("загрузка вернула HTTP %d",r.StatusCode)};b,e:=io.ReadAll(io.LimitReader(r.Body,max+1));if e==nil&&int64(len(b))>max{e=errors.New("файл превышает допустимый размер")};return b,e}
func checksumFor(c,n string)(string,error){for _,l:=range strings.Split(c,"\n"){f:=strings.Fields(l);if len(f)>=2&&strings.TrimPrefix(f[len(f)-1],"*")==n&&len(f[0])==64{if _,e:=hex.DecodeString(f[0]);e==nil{return strings.ToLower(f[0]),nil}}};return "",fmt.Errorf("SHA-256 для %s не найдена",n)}
func compareSemver(a,b string)int{p:=func(s string)[3]int{var x[3]int;z:=strings.Split(strings.TrimPrefix(strings.TrimSpace(s),"v"),".");for i:=0;i<len(z)&&i<3;i++{_,_=fmt.Sscanf(z[i],"%d",&x[i])};return x};x,y:=p(a),p(b);for i:=range x{if x[i]>y[i]{return 1};if x[i]<y[i]{return -1}};return 0}
func rollbackDir()string{return filepath.Join(appDataDir(),"rollback","previous")}
func rollbackStatePath()string{return filepath.Join(appDataDir(),"rollback","state.json")}
func hasRollback()bool{b,e:=os.ReadFile(rollbackStatePath());if e!=nil{return false};var s rollbackState;return json.Unmarshal(b,&s)==nil&&s.InstallDir!=""&&fileExists(filepath.Join(rollbackDir(),"PrivateVPN-Next.exe"))}
func fileExists(p string)bool{_,e:=os.Stat(p);return e==nil}
func prepareRollback(dir,version string)error{
 if !fileExists(filepath.Join(dir,"PrivateVPN-Next.exe")){return errors.New("не найден exe установленной версии")}
 if !fileExists(filepath.Join(dir,"unins000.exe")){return errors.New("обновление поддерживается для установки через Setup.exe; portable-версию обновляйте вручную")}
 base:=filepath.Join(appDataDir(),"rollback")
 if e:=os.RemoveAll(base);e!=nil{return e}
 if e:=os.MkdirAll(base,0700);e!=nil{return e}
 b,_:=json.MarshalIndent(rollbackState{InstallDir:dir,CreatedAt:time.Now(),FromVersion:version},"","  ")
 return os.WriteFile(rollbackStatePath(),b,0600)
}
func launchUpdateAfterExit(installer,installDir string)error{
 backup:=rollbackDir()
 script:=filepath.Join(appDataDir(),"updates","install-update.cmd")
 body:=fmt.Sprintf("@echo off\r\nsetlocal\r\n:waitapp\r\ntasklist /FI \"IMAGENAME eq PrivateVPN-Next.exe\" 2>NUL | find /I \"PrivateVPN-Next.exe\" >NUL\r\nif not errorlevel 1 (timeout /t 1 /nobreak >NUL & goto waitapp)\r\nrobocopy \"%s\" \"%s\" /MIR /R:2 /W:1 >NUL\r\nif errorlevel 8 exit /b 21\r\nstart /wait \"\" \"%s\" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /CLOSEAPPLICATIONS /DIR=\"%s\"\r\nexit /b %%errorlevel%%\r\n",installDir,backup,installer,installDir)
 if e:=os.WriteFile(script,[]byte(body),0600);e!=nil{return e}
 return exec.Command("cmd.exe","/c","start","",script).Start()
}
func launchRollback()error{b,e:=os.ReadFile(rollbackStatePath());if e!=nil{return errors.New("резервная копия предыдущей версии не найдена")};var s rollbackState;if e=json.Unmarshal(b,&s);e!=nil{return e};if !fileExists(filepath.Join(rollbackDir(),"PrivateVPN-Next.exe")){return errors.New("резервная копия повреждена")};script:=filepath.Join(appDataDir(),"rollback","restore.cmd");body:=fmt.Sprintf("@echo off\r\n:wait\r\ntasklist /FI \"IMAGENAME eq PrivateVPN-Next.exe\" 2>NUL | find /I \"PrivateVPN-Next.exe\" >NUL\r\nif not errorlevel 1 (timeout /t 1 /nobreak >NUL & goto wait)\r\nrobocopy \"%s\" \"%s\" /MIR /R:2 /W:1 >NUL\r\nif errorlevel 8 exit /b 22\r\nstart \"\" \"%s\"\r\ndel /q \"%s\" 2>NUL\r\nrmdir /s /q \"%s\" 2>NUL\r\n",rollbackDir(),s.InstallDir,filepath.Join(s.InstallDir,"PrivateVPN-Next.exe"),rollbackStatePath(),rollbackDir());if e=os.WriteFile(script,[]byte(body),0600);e!=nil{return e};return exec.Command("cmd.exe","/c","start","",script).Start()}
