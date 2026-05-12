unit LP_Crypto;

interface

uses
  System.SysUtils, System.Classes, System.Hash, System.NetEncoding;

function SHA256Hex(const AInput: string): string;
function HMACSHA256Hex(const AKey: TBytes; const AInput: string): string;
function HMACSHA256Bytes(const AKey, AInput: TBytes): TBytes;
function HKDF_SHA256(const AIKM, ASalt, AInfo: string): TBytes;
function BytesToHex(const ABytes: TBytes): string;

implementation

function BytesToHex(const ABytes: TBytes): string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to High(ABytes) do
    Result := Result + IntToHex(ABytes[I], 2);
  Result := LowerCase(Result);
end;

function SHA256Hex(const AInput: string): string;
var
  Bytes: TBytes;
begin
  Bytes := THashSHA2.GetHashBytes(AInput);
  Result := BytesToHex(Bytes);
end;

function HMACSHA256Bytes(const AKey, AInput: TBytes): TBytes;
begin
  Result := THashSHA2.GetHMACAsBytes(AInput, AKey);
end;

function HMACSHA256Hex(const AKey: TBytes; const AInput: string): string;
var
  InputBytes: TBytes;
  ResultBytes: TBytes;
begin
  InputBytes := TEncoding.UTF8.GetBytes(AInput);
  ResultBytes := HMACSHA256Bytes(AKey, InputBytes);
  Result := BytesToHex(ResultBytes);
end;

function HKDF_SHA256(const AIKM, ASalt, AInfo: string): TBytes;
var
  SaltBytes, IKMBytes, InfoBytes: TBytes;
  PRK: TBytes;
  Block: TBytes;
begin
  SaltBytes := TEncoding.UTF8.GetBytes(ASalt);
  IKMBytes  := TEncoding.UTF8.GetBytes(AIKM);
  InfoBytes := TEncoding.UTF8.GetBytes(AInfo);

  // Extract: PRK = HMAC-SHA256(salt, ikm)
  PRK := HMACSHA256Bytes(SaltBytes, IKMBytes);

  // Expand: T(1) = HMAC-SHA256(PRK, info || 0x01)
  SetLength(Block, Length(InfoBytes) + 1);
  if Length(InfoBytes) > 0 then
    Move(InfoBytes[0], Block[0], Length(InfoBytes));
  Block[Length(InfoBytes)] := 1;

  Result := HMACSHA256Bytes(PRK, Block);
  // Tronca a 32 byte
  SetLength(Result, 32);
end;

end.
