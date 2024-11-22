#!/usr/bin/perl
use strict;
use warnings;
use File::Basename;

# 파일 시그니처 정의
my %file_signatures = (

    'pdf'  => [ "%PDF" ],
    'gif'  => [ "GIF87a", "GIF89a" ],
    'png'  => [ "\x89PNG\x0d\x0a\x1a\x0a" ],
    'jpg'  => [ "\xff\xd8\xff\xe0", "\xff\xd8\xff\xe1", "\xff\xd8\xff\xe8", "\xff\xd8\xff\xdb", "\xff\xd8\xff\xee" ],
    'zip'  => [ "PK\x03\x04" ],
    'exe'  => [ "MZ" ],
    'msi'  => [ "MZ" ],
    'ico'  => [ "\x00\x00\x01\x00" ],
    'cur'  => [ "\x00\x00\x02\x00" ],
    'bmp'  => [ "BM" ],
    'tar'  => [ "ustar" ],
    'gz'   => [ "\x1f\x8b\x08", "\x1f\x9d", "\x1f\xa0" ],
    'avi'  => [ "RIFF" ],
    'wav'  => [ "RIFF" ],
    'mp3'  => [ "ID3", "\xff\xfb" ],
    'doc'  => [ "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "\xec\xa5\xc1\x00", "\xbe\x00\x00\x00\xab\x00\x00\x00" ],
    'xls'  => [ "\xfd\xff\xff\xff", "\xfe\xff" ],
    'ppt'  => [ "\x00\x6e\x1e\xf0", "\xfd\xff\xff\xff" ],
    'mp4'  => [ "\x00\x00\x00\x18ftyp" ],
    'mov'  => [ "moov" ],
    'docx' => [ "PK\x03\x04" ],
    'pptx' => [ "PK\x03\x04" ],
    'xlsx' => [ "PK\x03\x04" ],

);

# 파일 시그니처 읽기 함수
sub get_file_signature {
    
    my ($file) = @_;

    open my $fh, '<', $file or die "파일을 열 수 없습니다: '$file': $!";

    binmode $fh;

    read $fh, my $signature, 8;  # 최대 8바이트 읽기

    close $fh;

    return $signature;

}

# BOF 취약점 탐지 함수 (EXE 파일 전용)
sub check_bof_vulnerability {

    my ($file) = @_;

    open my $fh, '<', $file or die "파일을 열 수 없습니다: '$file': $!";

    binmode $fh;

    my $content;

    read $fh, $content, -s $file;  # 파일 전체 읽기

    close $fh;

    if ($content =~ /(\x90{8,}|A{256,})/) {

        return 1;  # BOF 가능성 있음

    }

    return 0;  # BOF 가능성 없음

}

# APK 및 IPA 디컴파일 함수
sub decompile_file {

    my ($file, $extension) = @_;

    if ($extension eq 'apk') {

        my $output_dir = "${file}_decompiled";

        system("jadx -d $output_dir $file") == 0

            or die "APK 디컴파일 실패: $!";

        print "APK 파일이 디컴파일되었습니다: $output_dir\n";

    } elsif ($extension eq 'ipa') {

        my $output_dir = "${file}_decompiled";

        system("class-dump -o $output_dir $file") == 0

            or die "IPA 디컴파일 실패: $!";

        print "IPA 파일이 디컴파일되었습니다: $output_dir\n";

    } else {

        die "지원되지 않는 디컴파일 형식: .$extension\n";

    }

}

# 메인 프로그램
if (@ARGV < 1) {

    die "사용법: $0 [-PE|-m] <파일 경로>\n";

}

my $option = "";
my $file;

if ($ARGV[0] eq '-PE' || $ARGV[0] eq '-m') {

    $option = $ARGV[0];

    $file = $ARGV[1] or die "파일 경로를 제공하세요.\n";

} else {

    $file = $ARGV[0];

}

my $extension = lc((fileparse($file, qr/\.[^.]*/))[2]);  # 확장자 추출

$extension =~ s/^\.//;  # '.' 제거

# 시그니처 정의 확인
if (!exists $file_signatures{$extension} && $option ne '-m') {

    die "지원되지 않는 파일 확장자: .$extension\n";

}

if ($option eq '-m') {

    if ($extension eq 'apk' || $extension eq 'ipa') {

        decompile_file($file, $extension);
        
    } else {

        die "-m 옵션은 APK 또는 IPA 파일에서만 사용할 수 있습니다.\n";

    }
} else {
    
    # 예상 시그니처 가져오기
    my $expected_signatures = $file_signatures{$extension};

    # 실제 시그니처 가져오기
    my $actual_signature = get_file_signature($file);

    # 시그니처 비교
    my $match_found = 0;

    foreach my $expected_signature (@$expected_signatures) {

        if ($actual_signature =~ /^\Q$expected_signature/) {

            $match_found = 1;

            last;

        }

    }

    if ($match_found) {

        print "파일 시그니처가 예상된 파일 유형과 일치합니다: .$extension\n";

        # EXE 파일 처리 (BOF 탐지)
        if ($option eq '-PE' && $extension eq 'exe') {

            if (check_bof_vulnerability($file)) {

                print "경고: $file 에서 잠재적인 BOF 취약점이 발견되었습니다.\n";

            } else {

                print "$file 에서 BOF 취약점이 발견되지 않았습니다.\n";

            }
        }

    } else {

        print "파일 시그니처가 일치하지 않습니다! 예상: .$extension, 실제: 다른 시그니처.\n";
   
    }

}

