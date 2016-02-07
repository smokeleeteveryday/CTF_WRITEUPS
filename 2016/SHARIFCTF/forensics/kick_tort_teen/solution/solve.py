"""
SharifCTF 2016 - Forensics - Kick Tort Teen (50 pts)

============================[ Smoke Leet Everyday ]============================
"""

#!/usr/bin/env python3

def main():

    data = []

    print('[+] Reading values', end='... ')
    with open('data.csv') as f:
        for line in f:
            for i in line.split(','):
                value = (int(i) - 78) // 3
                data.append(value)
    print('done')

    with open('fileXYZ.data', 'wb') as f:
        print('[+] Writing decoded bytes', end='... ')
        f.write(bytes(data))
        print('done')

        print('[+] Writing trailing bytes', end='...')
        f.write(bytes([98, 13, 0, 73, 19, 0, 94, 188, 0, 0, 0]))
        print('done')

    print('[+] Done: fileXYZ.data')


if __name__ == '__main__':
    main()
