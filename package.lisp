;;;; package.lisp

(defpackage #:bip0340
  (:use #:cl)
  (:export #:sign-message
	   #:verify-signature
	   #:generate-key
	   #:public-key))
