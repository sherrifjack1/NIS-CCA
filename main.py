def encryptText(plainText: str, key: str) -> str:
    #Verify Inputs
    if len(key) != 10: raise ValueError("Key is not 10 Characters.")
    plainText = ''.join([ch for ch in plainText.upper() if 'A' <= ch <= 'Z'])
    key = key.upper()
    
    #Padding & Initialization
    while len(plainText) % 10 != 0:
        plainText += 'X'
    cipherText = ""
    currentKey = key

    #Begin Encryption, 10 Character Block Loop
    for blockStart in range(0, len(plainText), 10):
        block = plainText[blockStart:blockStart + 10]
        cipherBlock = ""

        #Vigenere Encryption
        for i in range(10):
            p = ord(block[i]) - ord('A')
            k = ord(currentKey[i]) - ord('A')
            c = (p + k) % 26
            cipherBlock += chr(c + ord('A'))

        #Shift Key Mod Sum
        shiftValue = sum(ord(ch) - ord('A') for ch in currentKey) % 26

        #Shift Encryption
        shiftedBlock = ""
        for ch in cipherBlock:
            c = (ord(ch) - ord('A') + shiftValue) % 26
            shiftedBlock += chr(c + ord('A'))

        #Append Cipher Text, Set new Key
        cipherText += shiftedBlock
        currentKey = shiftedBlock
    #End Encryption, Return Cipher Text
    return cipherText


def decryptText(cipherText: str, key: str) -> str:
    #Verify Inputs
    if len(key) != 10: raise ValueError("Key is not 10 Characters.")
    cipherText = ''.join([ch for ch in cipherText.upper() if 'A' <= ch <= 'Z'])
    key = key.upper()

    #Initialization
    plainText = ""
    currentKey = key

    #Begin Decryption, 10 Character Block Loop
    for blockStart in range(0, len(cipherText), 10):
        cipherBlock = cipherText[blockStart:blockStart + 10]

        #Shift Key Mod Sum
        shiftValue = sum(ord(ch) - ord('A') for ch in currentKey) % 26

        #Shift Decryption
        unshiftedBlock = ""
        for ch in cipherBlock:
            c = (ord(ch) - ord('A') - shiftValue + 26) % 26
            unshiftedBlock += chr(c + ord('A'))

        #Vigenere Decryption
        plainBlock = ""
        for i in range(10):
            c = ord(unshiftedBlock[i]) - ord('A')
            k = ord(currentKey[i]) - ord('A')
            p = (c - k + 26) % 26
            plainBlock += chr(p + ord('A'))

        #Append Plain Text, Set new Key
        plainText += plainBlock
        currentKey = cipherBlock
    #End Decryption, Return Plain Text
    return plainText

def plaintextAttack(plainText: str, cipherText: str) -> str:
    #Verify Inputs
    plainText = ''.join(ch for ch in plainText.upper() if 'A' <= ch <= 'Z')
    cipherText = ''.join(ch for ch in cipherText.upper() if 'A' <= ch <= 'Z')

    #Padding & Length Validation
    padLength = (10 - (len(plainText) % 10)) % 10
    plainText += 'X' * padLength
    if len(cipherText) != len(plainText) or len(cipherText) % 10 != 0:
        raise ValueError("Length & Padding Mismatch with Cipher & Plain Texts")

    #Block First 10 Characters
    plainBlock = plainText[0:10]
    cipherBlock = cipherText[0:10]

    #Get Letter Differences between each Block
    perLetterDifferences = [(ord(cipherBlock[i]) - ord(plainBlock[i])) % 26 for i in range(10)]
    modSumOfDifferences = sum(perLetterDifferences) % 26

    #Using Moduler Inverse to Obtain Shift Value
    modInv11 = 19
    shiftValue = (modInv11 * modSumOfDifferences) % 26

    #Recover Key using Differences
    recoveredKey = ''.join(
        chr(((difference - shiftValue) % 26) + ord('A'))
        for difference in perLetterDifferences
    )

    return recoveredKey

#Testing
initialkey = "THISISATES"
initialPlainText = "HELLOMYNAMEISKUMAIL"
print("Entered:", initialPlainText)

resultCipherText = encryptText(initialPlainText, initialkey)
print("Cipher:", resultCipherText)

resultPlainText = decryptText(resultCipherText, initialkey)
print("Decrypted:", resultPlainText)

print("Initial Key:", initialkey)
resultKey = plaintextAttack(resultPlainText,resultCipherText)
print("Result Key:", resultKey)
    
#Attack Metric Test
import time
import random
import string
import statistics
import pprint
    
def runAttackMetrics(
    initialKey: str,
    lengths=(10, 50, 200, 1000),
    trialsPerLength=20,
    seed=0
):
    random.seed(seed)
    if len(initialKey) != 10:
        raise ValueError("Key is not 10 Characters.")
    results = {}
    for L in lengths:
        encryptTimes = []
        decryptTimes = []
        attackTimes = []
        successes = 0
        for t in range(trialsPerLength):
            plain = ''.join(random.choices(string.ascii_uppercase, k=L))
            t0 = time.perf_counter()
            cipher = encryptText(plain, initialKey)
            t1 = time.perf_counter()
            encryptTimes.append(t1 - t0)
            t0 = time.perf_counter()
            recovered = decryptText(cipher, initialKey)
            t1 = time.perf_counter()
            decryptTimes.append(t1 - t0)
            t0 = time.perf_counter()
            recoveredKey = plaintextAttack(plain, cipher)
            t1 = time.perf_counter()
            attackTimes.append(t1 - t0)
            if recoveredKey == initialKey:
                successes += 1
        def stats(lst):
            return {
                'count': len(lst),
                'mean_s': statistics.mean(lst),
                'stdev_s': statistics.stdev(lst) if len(lst) > 1 else 0.0,
                'min_s': min(lst),
                'max_s': max(lst)
            }
        results[L] = {
            'encrypt': stats(encryptTimes),
            'decrypt': stats(decryptTimes),
            'attack': stats(attackTimes),
            'success_rate': successes / trialsPerLength
        }
        print(f"Len={L:5}  Enc(ms)={results[L]['encrypt']['mean_s']*1000:7.2f} ±{results[L]['encrypt']['stdev_s']*1000:5.2f}"
              f"  Dec(ms)={results[L]['decrypt']['mean_s']*1000:7.2f} ±{results[L]['decrypt']['stdev_s']*1000:5.2f}"
              f"  Atk(ms)={results[L]['attack']['mean_s']*1000:7.3f}  Success={results[L]['success_rate']*100:.1f}%")
    return results

initialkey = "THISISATES"
metrics = runAttackMetrics(
    initialKey=initialkey,
    lengths=(10, 50, 200, 1000),
    trialsPerLength=20,
    seed=42
)
print("\nFull metrics:")
pprint.pprint(metrics)
    






