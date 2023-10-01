#!/bin/bash

for FILE in API*
do
	echo $FILE
	NUM=$(echo $FILE | cut -d'=' -f6)
	echo $NUM
	mv "$FILE" profile$NUM
done

for FILE in profile*
do
	mv "$FILE" "$FILE.py"
done

