;;;; bip0340.lisp

(in-package #:bip0340)

(defun make-tagged-sha256-digester (tag)
  (let ((prefix (crypto:digest-sequence
		 :sha256
		 (crypto:ascii-string-to-byte-array tag))))
    (let ((digester (crypto:make-digest :sha256)))
      (loop repeat 2 do (crypto:digest-sequence digester prefix))
      digester)))

(defmacro tagged-sha256-seq (tag &rest args)
  (alexandria:with-unique-names (digester)
    `(let ((,digester
	     (crypto:copy-digest
	      (load-time-value
	       (make-tagged-sha256-digester ,tag) t))))
       ,@(loop for arg in args
	       collect `(crypto:digest-sequence ,digester ,arg)))))

(deftype simple-ub8-vector (size)
  `(simple-array (unsigned-byte 8) (,size)))

(defun y-is-even (point-bytes)
  (or (= 2 (aref point-bytes 0))
      (and (= 4 (aref point-bytes 0))
	   (evenp (aref point-bytes 64)))))

(defun verify-signature (public-key message-hash signature)
  (declare (optimize (speed 3) (debug 1) (compilation-speed 0)))
  (check-type signature (simple-ub8-vector 64))
  (check-type message-hash (simple-ub8-vector 32))
  (check-type public-key (simple-ub8-vector 32))
  (handler-case
      (let* ((r (subseq signature 0 32))
	     (s (subseq signature 32 64))
	     (e0 (tagged-sha256-seq "BIP0340/challenge"
				    r public-key message-hash))
	     (e (crypto:octets-to-integer e0))
	     (minus-e (mod (- (the integer e)) crypto::+secp256k1-l+))
	     (pk-point (crypto::ec-decode-point
			:secp256k1
			(concatenate '(simple-ub8-vector *) #(2) public-key)))
	     (r-big
	       (crypto::ec-add
		(crypto::ec-scalar-mult crypto::+secp256k1-g+
					(crypto:octets-to-integer s))
		(crypto::ec-scalar-mult pk-point minus-e)))
	     (r-big-bytes
	       (if (crypto::ec-point-equal r-big
					   crypto::+secp256k1-point-at-infinity+)
		   (return-from verify-signature nil)
		   (crypto::ec-encode-point r-big)))
	     (r-bytes (subseq r-big-bytes 1 33)))
	(and
	 (y-is-even r-big-bytes)
	 (crypto::ec-point-on-curve-p pk-point)
	 (equalp r-bytes r)))
    (crypto:invalid-curve-point ())))

(defun generate-key ()
  (crypto:random-data 32))

(defun public-key (private-key)
  (check-type private-key (simple-ub8-vector 32))
  (let ((priv (crypto:make-private-key :secp256k1 :x private-key)))
    (subseq (crypto:secp256k1-key-y priv) 1 33)))

(defun sign-message (private-key message-hash
			    &optional (aux-data (crypto:random-data 32)
						aux-data-p))
  (flet ((retry ()
	   (if aux-data-p
	       (error "signing failed")
	       (return-from sign-message
		 (sign-message private-key message-hash)))))
    (let* ((secp-key (crypto:make-private-key :secp256k1 :x private-key))
	   (pk-point (crypto:secp256k1-key-y secp-key))
	   (pk-xonly (subseq pk-point 1 33))
	   (y-is-even (y-is-even pk-point))
	   (d (if y-is-even private-key
		  (crypto:integer-to-octets
		   (- crypto::+secp256k1-l+
		      (crypto:octets-to-integer private-key))
		   :n-bits 256)))
	   (tt (map '(simple-ub8-vector 32) 'logxor d
		    (tagged-sha256-seq "BIP0340/aux" aux-data)))
	   (rand
	     (tagged-sha256-seq "BIP0340/nonce" tt pk-xonly message-hash))
	   (k-prim (mod (crypto:octets-to-integer rand)
			crypto::+secp256k1-l+))
	   (r-point (crypto::ec-scalar-mult crypto::+secp256k1-g+ k-prim))
	   (r-xybytes (crypto::ec-encode-point r-point))
	   (r-y-is-even (y-is-even r-xybytes))
	   (k (if r-y-is-even k-prim
		  (- crypto::+secp256k1-l+ k-prim)))
	   (e (crypto:octets-to-integer
	       (tagged-sha256-seq "BIP0340/challenge"
				  (subseq r-xybytes 1 33)
				  pk-xonly
				  message-hash))))
      (when (zerop k-prim)
	(retry))
      (let ((sig (concatenate '(simple-ub8-vector *)
			      (subseq r-xybytes 1 33)
			      (crypto:integer-to-octets
			       (mod (+ k (* e (crypto:octets-to-integer d)))
				    crypto::+secp256k1-l+)
			       :n-bits 256))))
	(unless (verify-signature pk-xonly message-hash sig)
	  (retry))
	sig))))
