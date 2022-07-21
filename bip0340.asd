;;;; bip0340.asd

(asdf:defsystem #:bip0340
  :description "BIP-0340 signing and verification"
  :author "Anton Kovalenko <anton@sw4me.com>"
  :license  "Public Domain"
  :version "0.0.1"
  :serial t
  :depends-on ("alexandria"
	       "ironclad")
  :in-order-to ((asdf:test-op (asdf:test-op #:bip0340/test)))
  :components ((:file "package")
               (:file "bip0340")))

(asdf:defsystem #:bip0340/test
  :depends-on ("bip0340"
	       "fiveam"
	       "alexandria"
	       "ironclad")
  :components ((:file "t/tests"))
  :perform (asdf:test-op (o c)
			 (funcall (read-from-string "5am:run!")
				  :bip0340)))
