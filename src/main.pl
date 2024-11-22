#!/usr/bin/perl
use strict;
use warnings;
use File::Basename;

# 파일 시그니처 정의
my %file_signatures = (

    'exe' => "MZ",           # EXE 파일의 시그니처
    'png' => "\x89PNG",      # PNG 파일의 시그니처
    'jpg' => "\xFF\xD8\xFF", # JPG 파일의 시그니처
    'gif' => "GIF",          # GIF 파일의 시그니처
    'pdf' => "%PDF",         # PDF 파일의 시그니처
    # 추가적인 파일 형식 및 시그니처는 여기서 정의 가능

);

# 파일 시그니처 읽기 함수
sub get_file_signature {

    my ($file) = @_;
    open my $fh, '<', $file or die "파일을 열 수 없습니다: '$file': $!";
    binmode $fh;  # 이진 모드로 파일 열기
    read $fh, my $signature, 4;  # 처음 4바이트 읽기 (필요 시 길이 조정 가능)
    close $fh;
    return $signature;

}

# BOF 취약점 탐지 함수 (EXE 파일 전용)
sub check_bof_vulnerability {

    my ($file) = @_;
    
    # 간단한 BOF 탐지 로직: 실제 사용 시 더 정교한 분석 필요
    open my $fh, '<', $file or die "파일을 열 수 없습니다: '$file': $!";
    binmode $fh;  # 이진 모드로 파일 열기
    my $content;
    read $fh, $content, -s $file;  # 파일 전체 내용을 읽음
    close $fh;
    
    # 간단한 패턴 탐지: NOP sled(\x90) 또는 반복 문자 (A) 패턴
    if ($content =~ /(\x90{8,}|A{256,})/) { 
        return 1;  # BOF 가능성이 있음
    }
    return 0;  # BOF 가능성 없음

}

# 메인 프로그램
if (@ARGV != 1) {

    die "사용법: $0 <파일 경로>\n";

}

my $file = $ARGV[0];

my $extension = lc((fileparse($file, qr/\.[^.]*/))[2]);  # 파일 확장자 추출

$extension =~ s/^\.//;  # 확장자에서 선행 '.' 제거

if (!exists $file_signatures{$extension}) {

    die "지원되지 않는 파일 확장자: .$extension\n";

}

# 예상되는 시그니처 가져오기
my $expected_signature = $file_signatures{$extension};

# 실제 파일의 시그니처 가져오기
my $actual_signature = get_file_signature($file);

# 시그니처 비교
if ($actual_signature =~ /^\Q$expected_signature/) {

    print "파일 시그니처가 예상된 파일 유형과 일치합니다: .$extension\n";
    
    # EXE 파일일 경우 BOF 탐지
    if ($extension eq 'exe') {

        if (check_bof_vulnerability($file)) {

            print "경고: $file 에서 잠재적인 BOF 취약점이 발견되었습니다.\n";

        } else {

            print "$file 에서 BOF 취약점이 발견되지 않았습니다.\n";

        }

    }

} else {

    print "파일 시그니처가 일치하지 않습니다! 예상: .$extension, 실제: 다른 시그니처.\n";

}
