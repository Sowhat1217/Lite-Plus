package dbcore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	logger "github.com/nuomiiiii/lite/utils/log"
)

func renameSQLitePair(legacy, target string) error {
	if _, err := os.Stat(target); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if _, err := os.Stat(legacy); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		src := legacy + suffix
		dst := target + suffix
		if _, err := os.Stat(src); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		if err := os.Rename(src, dst); err != nil {
			return fmt.Errorf("rename %s to %s: %w", src, dst, err)
		}
	}
	logger.Infof("dbcore", "adopted database %s as %s", legacy, target)
	return nil
}

func alignStagedMainDatabase(stageDir string) (string, error) {
	targetBase := filepath.Base(resolveDatabaseFile())
	if targetBase == "" || targetBase == "." {
		targetBase = "lite.db"
	}
	target := filepath.Join(stageDir, targetBase)
	if fileExists(target) {
		return target, nil
	}
	alt := filepath.Join(stageDir, "lite.db")
	if !strings.EqualFold(targetBase, "lite.db") && fileExists(alt) {
		if err := renameSQLitePair(alt, target); err != nil {
			return "", err
		}
		return target, nil
	}
	return target, nil
}
