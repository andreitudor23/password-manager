import os
import time
from datetime import datetime
from typing import Optional

import cv2
import numpy as np


class FaceAuthManager:
    """
    Autentificare facială bazată pe:
      - Haar cascade pentru detectarea feței
      - LBPH face recognizer (din opencv-contrib) pentru recunoaștere
    """

    def __init__(self, model_path: str = "data/face_model/lbph_face.yml"):
        self.model_path = model_path
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)

        # detector simplu (vine odată cu OpenCV)
        cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
        self.detector = cv2.CascadeClassifier(cascade_path)

        self.recognizer: Optional[cv2.face_LBPHFaceRecognizer] = None
        self._load_model()

    # ----------------- model I/O -----------------
    def _load_model(self):
        if os.path.exists(self.model_path):
            self.recognizer = cv2.face.LBPHFaceRecognizer_create()
            self.recognizer.read(self.model_path)
        else:
            self.recognizer = None

    def _save_model(self):
        if self.recognizer is not None:
            self.recognizer.write(self.model_path)

    # ----------------- API public -----------------
    def is_enrolled(self) -> bool:
        return self.recognizer is not None

    def enroll(self, num_samples: int = 20) -> bool:
        """
        Pornește camera, ia câteva imagini cu fața ta și antrenează un model LBPH.
        ESC = anulează, SPACE = forțează captură.
        """
        #CAM_INDEX = 2
        cap = cv2.VideoCapture(1)
        if not cap.isOpened():
            print("[FaceAuth] Camera nu poate fi deschisă.")
            return False

        print("[FaceAuth] Enrolare: privește spre cameră. SPACE = captură, ESC = anulare")

        images = []
        labels = []

        captured = 0
        try:
            while captured < num_samples:
                ret, frame = cap.read()
                if not ret:
                    break

                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                faces = self.detector.detectMultiScale(gray, scaleFactor=1.2,
                                                       minNeighbors=5, minSize=(80, 80))

                for (x, y, w, h) in faces:
                    # desenăm doar ca feedback vizual
                    cv2.rectangle(frame, (x, y), (x+w, y+h), (0, 255, 0), 2)

                cv2.putText(
                    frame,
                    f"Capturi: {captured}/{num_samples}",
                    (10, 20),
                    cv2.FONT_HERSHEY_SIMPLEX,
                    0.6,
                    (255, 255, 255),
                    2,
                )

                cv2.imshow("Enroll face", frame)
                key = cv2.waitKey(1) & 0xFF

                if key == 27:  # ESC
                    print("[FaceAuth] Enrolare anulata.")
                    return False

                # captură automată când găsim o față, sau la SPACE
                do_capture = key == 32 or len(faces) > 0
                if do_capture and len(faces) > 0:
                    (x, y, w, h) = faces[0]
                    roi = gray[y:y+h, x:x+w]
                    roi = cv2.resize(roi, (200, 200))
                    images.append(roi)
                    labels.append(1)  # eticheta "1" = utilizatorul
                    captured += 1
        finally:
            cap.release()
            cv2.destroyAllWindows()

        if not images:
            print("[FaceAuth] Nu s-au colectat imagini suficiente.")
            return False

        # antrenăm modelul LBPH
        recognizer = cv2.face.LBPHFaceRecognizer_create()
        recognizer.train(images, np.array(labels))
        self.recognizer = recognizer
        self._save_model()
        print("[FaceAuth] Enrolare finalizata:", datetime.now())
        return True

    def verify(self, timeout_seconds: int = 10, threshold: float = 70.0) -> bool:
        """
        Verifică fața față de modelul LBPH.
        returnează True dacă scorul (confidence) e sub pragul dat.
        """
        if self.recognizer is None:
            print("[FaceAuth] Nu există model facial salvat.")
            return False

        cap = cv2.VideoCapture(1)
        if not cap.isOpened():
            print("[FaceAuth] Camera nu poate fi deschisă.")
            return False

        print("[FaceAuth] Verificare: privește spre cameră. ESC = anulare")
        start = time.time()

        try:
            while time.time() - start < timeout_seconds:
                ret, frame = cap.read()
                if not ret:
                    break

                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                faces = self.detector.detectMultiScale(gray, scaleFactor=1.2,
                                                       minNeighbors=5, minSize=(80, 80))

                label_text = "Caut fata..."
                color = (0, 255, 255)

                for (x, y, w, h) in faces:
                    roi = gray[y:y+h, x:x+w]
                    roi = cv2.resize(roi, (200, 200))

                    label, confidence = self.recognizer.predict(roi)
                    # în LBPH, confidence mai mic = mai sigur
                    if label == 1 and confidence < threshold:
                        label_text = f"OK ({confidence:.1f})"
                        color = (0, 255, 0)
                        cv2.rectangle(frame, (x, y), (x+w, y+h), color, 2)
                        cv2.putText(frame, label_text, (x, y-10),
                                    cv2.FONT_HERSHEY_SIMPLEX, 0.6, color, 2)
                        cv2.imshow("Verify face", frame)
                        cap.release()
                        cv2.destroyAllWindows()
                        print("[FaceAuth] MATCH, conf:", confidence)
                        return True
                    else:
                        label_text = f"Respins ({confidence:.1f})"
                        color = (0, 0, 255)
                        cv2.rectangle(frame, (x, y), (x+w, y+h), color, 2)

                cv2.putText(frame, label_text, (10, 20),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.6, color, 2)
                cv2.imshow("Verify face", frame)

                key = cv2.waitKey(1) & 0xFF
                if key == 27:  # ESC
                    print("[FaceAuth] Verificare anulata.")
                    return False

        finally:
            cap.release()
            cv2.destroyAllWindows()

        print("[FaceAuth] Nu s-a gasit match in timp util.")
        return False
